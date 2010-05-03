//////////////////////////////////////////////////////////////
//
// x86 Instruction Manipulator: Decoder/Generator/Encoder v1.0
//
// (x) Pluf
//
//////////////////////////////////////////////////////////////

#ifndef __X86IM_GEN_H__
#define __X86IM_GEN_H__

#define X86IM_GEN_R1_R2( r1, r2 )                           ( ( ( ( unsigned char )(r1) & 0xF ) << 4 ) | ( ( unsigned char )(r2) & 0xF ) )
#define X86IM_GEN_R2_R1( r2, r1 )                           ( ( ( ( unsigned char )(r1) & 0xF ) << 4 ) | ( ( unsigned char )(r2) & 0xF ) )
#define X86IM_GEN_RG_MM( rg )                               ( ( ( unsigned char )(rg) & 0xF ) << 4 )
#define X86IM_GEN_MM_RG( rg )                               ( ( ( unsigned char )(rg) & 0xF ) << 4 )
#define X86IM_GEN_RG_IM( rg )                               ( ( unsigned char )(rg) & 0xF )
#define X86IM_GEN_OP_RG( rg )                               ( ( unsigned char )(rg) & 0xF )
#define X86IM_GEN_AC_RG( rg )                               ( ( unsigned char )(rg) & 0xF )
#define X86IM_GEN_SREG2( sreg )                             ( ( ( unsigned char )( sreg ) & 0x3 ) << 3 )
#define X86IM_GEN_SREG3( sreg )                             ( ( ( ( unsigned char )( sreg ) & 0x7 ) << 3 ) << 8 )
#define X86IM_GEN_RG_CRX( rg, crx )                         ( ( ( ( unsigned char )(crx) & 0xF ) << 4 ) | ( ( unsigned char )(rg) & 0xF ) )
#define X86IM_GEN_CRX_RG( rg, crx )                         ( ( ( ( unsigned char )(crx) & 0xF ) << 4 ) | ( ( unsigned char )(rg) & 0xF ) )
#define X86IM_GEN_RG_DRX( rg, drx )                         ( ( ( ( unsigned char )(drx) & 0xF ) << 4 ) | ( ( unsigned char )(rg) & 0xF ) )
#define X86IM_GEN_DRX_RG( drx, rg )                         ( ( ( ( unsigned char )(drx) & 0xF ) << 4 ) | ( ( unsigned char )(rg) & 0xF ) )
#define X86IM_GEN_RG_SRX( rg, srx )                         ( ( ( ( unsigned char )(srx) & 0xF ) << 4 ) | ( ( unsigned char )(rg) & 0xF ) )
#define X86IM_GEN_SRX_RG( srx, rg )                         ( ( ( ( unsigned char )(srx) & 0xF ) << 4 ) | ( ( unsigned char )(rg) & 0xF ) )
#define X86IM_GEN_MM_SRX( srx )                             ( ( ( unsigned char )(srx) & 0xF ) << 4 )
#define X86IM_GEN_SRX_MM( srx )                             ( ( ( unsigned char )(srx) & 0xF ) << 4 )
#define X86IM_GEN_TTTN( tn )                                ( ( (tn) & 0xF ) << 8 )
#define X86IM_GEN_TTTN_R1_R2( tn, r1, r2 )                  X86IM_GEN_TTTN(tn) | X86IM_GEN_R1_R2( r1, r2 )
#define X86IM_GEN_TTTN_RG_MM( tn, rg )                      X86IM_GEN_TTTN(tn) | X86IM_GEN_RG_MM( rg )
#define X86IM_GEN_TTTN_RG( tn, rg )                         X86IM_GEN_TTTN(tn) | X86IM_GEN_OP_RG( rg )
#define X86IM_GEN_IMM1_IMM2( imm1, imm2 )                   ( ( ( unsigned short )(imm1) << 8 ) | ( unsigned char )(imm2) )
#define X86IM_GEN_STX( stx )                                ( ( unsigned char )(stx) & 0xF )
#define X86IM_GEN_ST0_STX( stx )                            ( ( unsigned char )(stx) & 0xF )
#define X86IM_GEN_STX_ST0( stx )                            ( ( unsigned char )(stx) & 0xF )
#define X86IM_GEN_MXR1_MXR2( mxr1, mxr2 )                   ( ( ( ( unsigned char )(mxr1) & 0xF ) << 4 ) | ( ( unsigned char )(mxr2) & 0xF ) )
#define X86IM_GEN_MXR2_MXR1( mxr2, mxr1 )                   ( ( ( ( unsigned char )(mxr1) & 0xF ) << 4 ) | ( ( unsigned char )(mxr2) & 0xF ) )
#define X86IM_GEN_MXR1_R2( mxrg, rg )                       ( ( ( ( unsigned char )(mxr1) & 0xF ) << 4 ) | ( ( unsigned char )(r2) & 0xF ) )
#define X86IM_GEN_R1_MXR2( rg, mxrg )                       ( ( ( ( unsigned char )(r1) & 0xF ) << 4 ) | ( ( unsigned char )(mxr2) & 0xF ) )
#define X86IM_GEN_MXRG_MM( mxrg )                           ( ( ( unsigned char )(mxrg) & 0xF ) << 4 )
#define X86IM_GEN_MM_MXRG( mxrg )                           ( ( ( unsigned char )(mxrg) & 0xF ) << 4 )
#define X86IM_GEN_XMR1_XMR2( xmr1, xmr2 )                   ( ( ( ( unsigned char )(xmr1) & 0xF ) << 4 ) | ( ( unsigned char )(xmr2) & 0xF ) )
#define X86IM_GEN_XMR1_MXR2( xmr1, mxr2 )                   ( ( ( ( unsigned char )(xmr1) & 0xF ) << 4 ) | ( ( unsigned char )(mxr2) & 0xF ) )
#define X86IM_GEN_MXR1_XMR2( mxr1, xmr2 )                   ( ( ( ( unsigned char )(mxr1) & 0xF ) << 4 ) | ( ( unsigned char )(xmr2) & 0xF ) )
#define X86IM_GEN_XMR2_XMR1( xmr2, xmr1 )                   ( ( ( ( unsigned char )(xmr1) & 0xF ) << 4 ) | ( ( unsigned char )(xmr2) & 0xF ) )
#define X86IM_GEN_XMR1_R2( xmr1, r2 )                       ( ( ( ( unsigned char )(xmr1) & 0xF ) << 4 ) | ( ( unsigned char )(r2) & 0xF ) )
#define X86IM_GEN_R1_XMR2( r1, xmr2 )                       ( ( ( ( unsigned char )(r1) & 0xF ) << 4 ) | ( ( unsigned char )(xmr2) & 0xF ) )
#define X86IM_GEN_XMRG_MM( xmrg )                           ( ( ( unsigned char )(xmrg) & 0xF ) << 4 )
#define X86IM_GEN_MM_XMRG( xmrg )                           ( ( ( unsigned char )(mxrg) & 0xF ) << 4 )

#define X86IM_GEN_OAT_BYTE                                  0x01000000
#define X86IM_GEN_OAT_WORD                                  0x02000000
#define X86IM_GEN_OAT_DWORD                                 0x04000000
#define X86IM_GEN_OAT_QWORD                                 0x08000000
#define X86IM_GEN_OAT_SIGN                                  0x10000000
#define X86IM_GEN_OAT_PACKED                                0x20000000
#define X86IM_GEN_OAT_NON_PACKED                            0x40000000

#define X86IM_GEN_OAT_NPO_B                                 X86IM_GEN_OAT_NON_PACKED|X86IM_GEN_OAT_BYTE
#define X86IM_GEN_OAT_NPO_W                                 X86IM_GEN_OAT_NON_PACKED|X86IM_GEN_OAT_WORD
#define X86IM_GEN_OAT_NPO_D                                 X86IM_GEN_OAT_NON_PACKED|X86IM_GEN_OAT_DWORD
#define X86IM_GEN_OAT_NPO_Q                                 X86IM_GEN_OAT_NON_PACKED|X86IM_GEN_OAT_QWORD

#define X86IM_GEN_OAT_PO_B                                  X86IM_GEN_OAT_PACKED|X86IM_GEN_OAT_BYTE
#define X86IM_GEN_OAT_PO_W                                  X86IM_GEN_OAT_PACKED|X86IM_GEN_OAT_WORD
#define X86IM_GEN_OAT_PO_D                                  X86IM_GEN_OAT_PACKED|X86IM_GEN_OAT_DWORD
#define X86IM_GEN_OAT_PO_BW                                 X86IM_GEN_OAT_PO_B
#define X86IM_GEN_OAT_PO_WD                                 X86IM_GEN_OAT_PO_W
#define X86IM_GEN_OAT_PO_DQ                                 X86IM_GEN_OAT_PO_D

#define X86IM_GEN_OAT_GET_PO_SIZE( x )                      ( ( (x)->options >> 25 ) & 0x3 )

#define X86IM_GEN_AM_DISP32( af, d32 )                      ( unsigned long )( (af) | X86IM_IO_MOP_AMC_DISP32 ), (d32)
#define X86IM_GEN_AM_DISP32_SIB1( af, d32 )                 ( unsigned long )( (af) | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB1 ), (d32)
#define X86IM_GEN_AM_DISP32_SIB2( af, d32 )                 ( unsigned long )( (af) | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB2 ), (d32)
#define X86IM_GEN_AM_DISP32_SIB3( af, d32 )                 ( unsigned long )( (af) | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB3 ), (d32)
#define X86IM_GEN_AM_DISP32_SIB4( af, d32 )                 ( unsigned long )( (af) | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB4 ), (d32)

#define X86IM_GEN_AM_BASE( af, b )                          ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE ) ), (0)
#define X86IM_GEN_AM_BASE_SIB1( af, b )                     ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB1 ) ), (0)
#define X86IM_GEN_AM_BASE_SIB2( af, b )                     ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB2 ) ), (0)
#define X86IM_GEN_AM_BASE_SIB3( af, b )                     ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB3 ) ), (0)
#define X86IM_GEN_AM_BASE_SIB4( af, b )                     ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB4 ) ), (0)   

#define X86IM_GEN_AM_BASE_DISP8( af, b, d8 )                ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 ) ), (d8)
#define X86IM_GEN_AM_BASE_DISP8_SIB1( af, b, d8 )           ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB1 ) ), (d8)
#define X86IM_GEN_AM_BASE_DISP8_SIB2( af, b, d8 )           ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB2 ) ), (d8)
#define X86IM_GEN_AM_BASE_DISP8_SIB3( af, b, d8 )           ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB3 ) ), (d8)
#define X86IM_GEN_AM_BASE_DISP8_SIB4( af, b, d8 )           ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB4 ) ), (d8)

#define X86IM_GEN_AM_BASE_DISP32( af, b, d32 )              ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 ) ), (d32)
#define X86IM_GEN_AM_BASE_DISP32_SIB1( af, b, d32 )         ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB1 ) ), (d32)
#define X86IM_GEN_AM_BASE_DISP32_SIB2( af, b, d32 )         ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB2 ) ), (d32)
#define X86IM_GEN_AM_BASE_DISP32_SIB3( af, b, d32 )         ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB3 ) ), (d32)
#define X86IM_GEN_AM_BASE_DISP32_SIB4( af, b, d32 )         ( unsigned long )( ( ( ( unsigned char )(b) & 0xF ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB4 ) ), (d32)

#define X86IM_GEN_AM_BASE_INDEX( af, b, i )                 ( unsigned long )( ( ( ( ( ( unsigned char )(i) & 0xF ) << 4 ) | ( ( unsigned char )(b) & 0xF ) ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX ) ), (0)
#define X86IM_GEN_AM_BASE_INDEX_DISP8( af, b, i, d8 )       ( unsigned long )( ( ( ( ( ( unsigned char )(i) & 0xF ) << 4 ) | ( ( unsigned char )(b) & 0xF ) ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP8 ) ), (d8)
#define X86IM_GEN_AM_BASE_INDEX_DISP32( af, b, i, d32 )     ( unsigned long )( ( ( ( ( ( unsigned char )(i) & 0xF ) << 4 ) | ( ( unsigned char )(b) & 0xF ) ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 ) ), (d32)

#define X86IM_GEN_AM_BASE_SINDEX( af, b, s, i )             ( unsigned long )( ( ( ( ( ( unsigned char )(s) & 0xE ) << 8 ) | ( ( ( ( unsigned char )(i) & 0xF ) << 4 ) | ( ( unsigned char )(b) & 0xF ) ) ) << 16 )  | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_SCALE ) ), (0)
#define X86IM_GEN_AM_BASE_SINDEX_DISP8( af, b, s, i, d8 )   ( unsigned long )( ( ( ( ( ( unsigned char )(s) & 0xE ) << 8 ) | ( ( ( ( unsigned char )(i) & 0xF ) << 4 ) | ( ( unsigned char )(b) & 0xF ) ) ) << 16 )  | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_DISP8 ) ), (d8)
#define X86IM_GEN_AM_BASE_SINDEX_DISP32( af, b, s, i, d32 ) ( unsigned long )( ( ( ( ( ( unsigned char )(s) & 0xE ) << 8 ) | ( ( ( ( unsigned char )(i) & 0xF ) << 4 ) | ( ( unsigned char )(b) & 0xF ) ) ) << 16 )  | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_DISP32 ) ), (d32)

#define X86IM_GEN_AM_INDEX_DISP32( af, i, d32 )             ( unsigned long )( ( ( ( unsigned char )(i) & 0xF ) << 20 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 ) ), (d32)
#define X86IM_GEN_AM_SINDEX_DISP32( af, s, i, d32 )         ( unsigned long )( ( ( ( ( ( unsigned char )(s) & 0xE ) << 8 ) | ( ( ( ( unsigned char )(i) & 0xF ) << 4 ) ) ) << 16 ) | ( unsigned short )( (af) | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_DISP32 ) ), (d32)

// GPI

#define X86IM_GEN_CODE_AAA                                  0x00000037
#define X86IM_GEN_AAA( io )                                 x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_AAA, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_AAD                                  0x00000AD5
#define X86IM_GEN_AAD( io )                                 x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_AAD, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_AAM                                  0x00000AD4
#define X86IM_GEN_AAM( io )                                 x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_AAM, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_AAS                                  0x0000003F
#define X86IM_GEN_AAS( io )                                 x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_AAS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CLC                                  0x000000F8
#define X86IM_GEN_CLC( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_CLC, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CLD                                  0x000000FC
#define X86IM_GEN_CLD( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_CLD, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CLI                                  0x000000FA
#define X86IM_GEN_CLI( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_CLI, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CLTS                                 0x0000060F
#define X86IM_GEN_CLTS( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_CLTS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CMC                                  0x000000F5
#define X86IM_GEN_CMC( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_CMC, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CPUID                                0x0000A20F
#define X86IM_GEN_CPUID( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_CPUID, 0, 0, 0, 0 )               

#define X86IM_GEN_CODE_DAA                                  0x00000027
#define X86IM_GEN_DAA( io )                                 x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_DAA, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_DAS                                  0x0000002F
#define X86IM_GEN_DAS( io )                                 x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_DAS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_HLT                                  0x000000F4
#define X86IM_GEN_HLT( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_HLT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_INVD                                 0x0000080F
#define X86IM_GEN_INVD( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_INVD, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_INVLPG                               0x0038010F
#define X86IM_GEN_INVLPG( io, mode, mm )                    x86im_gen( io, mode, X86IM_GEN_CODE_INVLPG, 0, mm, 0)

#define X86IM_GEN_CODE_LAHF                                 0x0000009F
#define X86IM_GEN_LAHF( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_LAHF, 0, 0, 0,0 )

#define X86IM_GEN_CODE_LEAVE                                0x000000C9
#define X86IM_GEN_LEAVE( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_LEAVE, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_LGDT                                 0x0010010F
#define X86IM_GEN_LGDT( io, mode, mm )                      x86im_gen( io, mode, X86IM_GEN_CODE_LGDT, 0, mm, 0 )

#define X86IM_GEN_CODE_LIDT                                 0x0018010F
#define X86IM_GEN_LIDT( io, mode, mm )                      x86im_gen( io, mode, X86IM_GEN_CODE_LIDT, 0, mm, 0 )

#define X86IM_GEN_CODE_RDMSR                                0x0000320F
#define X86IM_GEN_RDMSR( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_RDMSR, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_RDPMC                                0x0000330F
#define X86IM_GEN_RDPMC( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_RDPMC, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_RDTSC                                0x0000310F
#define X86IM_GEN_RDTSC( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_RDTSC, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_RSM                                  0x0000AA0F
#define X86IM_GEN_RSM( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_RSM, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_SAHF                                 0x0000009E
#define X86IM_GEN_SAHF( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_SAHF, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_SGDT                                 0x0000010F
#define X86IM_GEN_SGDT( io, mode, mm )                      x86im_gen( io, mode, X86IM_GEN_CODE_SGDT, 0, mm, 0 )

#define X86IM_GEN_CODE_SIDT                                 0x0008010F
#define X86IM_GEN_SIDT( io, mode, mm )                      x86im_gen( io, mode, X86IM_GEN_CODE_SIDT, 0, mm, 0 )
                   
#define X86IM_GEN_CODE_STC                                  0x000000F9
#define X86IM_GEN_STC( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_STC, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_STD                                  0x000000FD
#define X86IM_GEN_STD( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_STD, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_STI                                  0x000000FB
#define X86IM_GEN_STI( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_STI, 0, 0, 0, 0 )
    
#define X86IM_GEN_CODE_UD2                                  0x00000B0F
#define X86IM_GEN_UD2( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_UD2, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_WAIT                                 0x0000009B
#define X86IM_GEN_WAIT( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_WAIT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_WBINVD                               0x0000090F
#define X86IM_GEN_WBINVD( io, mode )                        x86im_gen( io, mode, X86IM_GEN_CODE_WBINVD, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_WRMSR                                0x0000300F
#define X86IM_GEN_WRMSR( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_WRMSR, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_XLAT                                 0x000000D7
#define X86IM_GEN_XLAT( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_XLAT, 0, 0, 0, 0 )

// imm1=16b, imm2=8b
#define X86IM_GEN_CODE_ENTER                                0x000000C8
#define X86IM_GEN_ENTER( io, mode, imm1, imm2 )             x86im_gen( io, mode, X86IM_GEN_CODE_ENTER, 0, 0, 0, X86IM_GEN_IMM1_IMM2( imm1, imm2 ) )

#define X86IM_GEN_CODE_SYSENTER                             0x0000340F
#define X86IM_GEN_SYSENTER( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_SYSENTER, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_SYSEXIT                              0x0000350F
#define X86IM_GEN_SYSEXIT( io, mode )                       x86im_gen( io, mode, X86IM_GEN_CODE_SYSEXIT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_SYSCALL                              0x0000050F
#define X86IM_GEN_SYSCALL( io )                             x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_SYSCALL, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_SYSRET                               0x0000070F
#define X86IM_GEN_SYSRET( io )                              x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_SYSRET, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_SWAPGS                               0x00F8010F
#define X86IM_GEN_SWAPGS( io )                              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SWAPGS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_NOP                                  0x00000090
#define X86IM_GEN_NOP( io, mode )                           x86im_gen( io, mode, X86IM_GEN_CODE_NOP, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_BOUND                                0x00000062

#define X86IM_GEN_BOUND_WORD( io, rg, mm )                  x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BOUND, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BOUND_DWORD( io, rg, mm )                 x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BOUND, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_CODE_BSWAP                                0x0000C80F

#define X86IM_GEN_BSWAP_DWORD( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BSWAP, rg, 0, 0, 0 ) 
#define X86IM_GEN_BSWAP_QWORD( io, rg )                     x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BSWAP, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_CMPSX                                0x000000A6

#define X86IM_GEN_CMPSB( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMPSX, 0, 0, 0, 0 )
#define X86IM_GEN_CMPSW( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMPSX, 0, 0, 0, 0 )
#define X86IM_GEN_CMPSD( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMPSX, 0, 0, 0, 0 )
#define X86IM_GEN_CMPSQ( io )                               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMPSX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_INSX                                 0x0000006C

#define X86IM_GEN_INSB( io, mode )                          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_INSX, 0, 0, 0, 0 )
#define X86IM_GEN_INSW( io, mode )                          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_INSX, 0, 0, 0, 0 )
#define X86IM_GEN_INSD( io, mode )                          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_INSX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_IRET                                 0x000000CF

#define X86IM_GEN_IRET( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_IRET, 0, 0, 0, 0 )
#define X86IM_GEN_IRETQ( io )                               x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_IRET, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_LDS                                  0x000000C5

#define X86IM_GEN_LDS_WORD( io, rg, mm )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LDS, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LDS_DWORD( io, rg, mm )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LDS, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_LEA                                  0x0000008D

#define X86IM_GEN_LEA_WORD( io, mode, rg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LEA, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LEA_DWORD( io, mode, rg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LEA, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LEA_QWORD( io, rg, mm )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LEA, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_LES                                  0x000000C4

#define X86IM_GEN_LES_WORD( io, rg, mm )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LES, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LES_DWORD( io, rg, mm )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LES, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_LFS                                  0x0000B40F

#define X86IM_GEN_LFS_WORD( io, mode, rg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LFS, X86IM_GEN_RG_MM( rg ), mm, 0 )                 
#define X86IM_GEN_LFS_DWORD( io, mode, rg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LFS, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LFS_QWORD( io, rg, mm )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LFS, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_LGS                                  0x0000B50F

#define X86IM_GEN_LGS_WORD( io, mode, rg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LGS, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LGS_DWORD( io, mode, rg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LGS, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LGS_QWORD( io, rg, mm )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LGS, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_LODSX                                0x000000AC

#define X86IM_GEN_LODSB( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_LODSX, 0, 0, 0, 0 )
#define X86IM_GEN_LODSW( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LODSX, 0, 0, 0, 0 )
#define X86IM_GEN_LODSD( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LODSX, 0, 0, 0, 0 )
#define X86IM_GEN_LODSQ( io )                               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LODSX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_LSS                                  0x0000B20F

#define X86IM_GEN_LSS_WORD( io, mode, rg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LSS, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LSS_DWORD( io, mode, rg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LSS, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LSS_QWORD( io, rg, mm )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LSS, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_MOVSX                                0x000000A4

#define X86IM_GEN_MOVSB( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOVSX, 0, 0, 0, 0 )
#define X86IM_GEN_MOVSW( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVSX, 0, 0, 0, 0 )
#define X86IM_GEN_MOVSD( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVSX, 0, 0, 0, 0 )
#define X86IM_GEN_MOVSQ( io )                               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVSX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_OUTSX                                0x0000006E

#define X86IM_GEN_OUTSB( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OUTSX, 0, 0, 0, 0 )
#define X86IM_GEN_OUTSW( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OUTSX, 0, 0, 0, 0 )
#define X86IM_GEN_OUTSD( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OUTSX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_SCASX                                0x000000AE

#define X86IM_GEN_SCASB( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SCASX, 0, 0, 0, 0 )
#define X86IM_GEN_SCASW( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SCASX, 0, 0, 0, 0 )
#define X86IM_GEN_SCASD( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SCASX, 0, 0, 0, 0 )
#define X86IM_GEN_SCASQ( io )                               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SCASX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_STOSX                                0x000000AA

#define X86IM_GEN_STOSB( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_STOSX, 0, 0, 0, 0 )
#define X86IM_GEN_STOSW( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_STOSX, 0, 0, 0, 0 )
#define X86IM_GEN_STOSD( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_STOSX, 0, 0, 0, 0 )
#define X86IM_GEN_STOSQ( io )                               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_STOSX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CMPXCHGXX                            0x0008C70F

#define X86IM_GEN_CMPXCHG8B( io, mode, mm )                 x86im_gen( io, mode, X86IM_GEN_CODE_CMPXCHGXX, 0, mm, 0 )
#define X86IM_GEN_CMPXCHG16B( io, mm )                      x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMPXCHGXX, 0, mm, 0 )

#define X86IM_GEN_CODE_CONVERT_A                            0x00000098

#define X86IM_GEN_CBW( io, mode )                           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CONVERT_A, 0, 0, 0, 0 )
#define X86IM_GEN_CWDE( io, mode )                          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CONVERT_A, 0, 0, 0, 0 )
#define X86IM_GEN_CDQE( io )                                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CONVERT_A, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_CONVERT_B                            0x00000099

#define X86IM_GEN_CWD( io, mode )                           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CONVERT_B, 0, 0, 0, 0 )
#define X86IM_GEN_CDQ( io, mode )                           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CONVERT_B, 0, 0, 0, 0 )
#define X86IM_GEN_CQD( io )                                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CONVERT_B, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_INTN                                 0x000000CD
#define X86IM_GEN_CODE_INT3                                 0x000000CC
#define X86IM_GEN_CODE_INTO                                 0x000000CE

#define X86IM_GEN_INTN( io, mode )                          x86im_gen( io, mode, X86IM_GEN_CODE_INTN, 0, 0, 0, 0 )
#define X86IM_GEN_INT3( io, mode, imm8 )                    x86im_gen( io, mode, X86IM_GEN_CODE_INT3, 0, 0, 0, imm8 )
#define X86IM_GEN_INTO( io )                                x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_INTO, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_LOOP                                 0x000000E2
#define X86IM_GEN_CODE_LOOPE                                0x000000E1
#define X86IM_GEN_CODE_LOOPNE                               0x000000E0

#define X86IM_GEN_LOOP( io, mode, imm8 )                    x86im_gen( io, mode, X86IM_GEN_CODE_LOOP, 0, 0, 0, imm8 )
#define X86IM_GEN_LOOPE( io, mode, imm8 )                   x86im_gen( io, mode, X86IM_GEN_CODE_LOOPE, 0, 0, 0, imm8 )
#define X86IM_GEN_LOOPNE( io, mode, imm8 )                  x86im_gen( io, mode, X86IM_GEN_CODE_LOOPNE, 0, 0, 0, imm8 )

#define X86IM_GEN_CODE_ADC_MM_RG                            0x00000010
#define X86IM_GEN_CODE_ADC_R2_R1                            0x0000C010
#define X86IM_GEN_CODE_ADC_RG_MM                            0x00000012
#define X86IM_GEN_CODE_ADC_R1_R2                            0x0000C012
#define X86IM_GEN_CODE_ADC_MM_IM                            0x00001080
#define X86IM_GEN_CODE_ADC_RG_IM                            0x0000D080
#define X86IM_GEN_CODE_ADC_AC_IM                            0x00000014

#define X86IM_GEN_ADC_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADC_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_ADC_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADC_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_ADC_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADC_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_ADC_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADC_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_ADC_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADC_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_ADC_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADC_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_ADC_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADC_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_ADC_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADC_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_ADC_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADC_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_ADC_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADC_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_ADC_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADC_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_ADC_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADC_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_ADC_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADC_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )  
#define X86IM_GEN_ADC_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADC_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_ADC_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADC_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_ADC_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADC_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_ADC_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm )
#define X86IM_GEN_ADC_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm )
#define X86IM_GEN_ADC_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm )
#define X86IM_GEN_ADC_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm )

#define X86IM_GEN_ADC_MM_IM_SBYTE( io, mode, mm, imm8 )     x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ADC_MM_IM_SWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ADC_MM_IM_SDWORD( io, mode, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ADC_MM_IM_SQWORD( io, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_ADC_RG_IM_BYTE( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_ADC_RG_IM_WORD( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_ADC_RG_IM_DWORD( io, mode, rg, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_ADC_RG_IM_QWORD( io, rg, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )

#define X86IM_GEN_ADC_RG_IM_SBYTE( io, mode, rg8, imm8 )    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_ADC_RG_IM_SWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ADC_RG_IM_SDWORD( io, mode, rg, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ADC_RG_IM_SQWORD( io, rg, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  

#define X86IM_GEN_ADC_AC_IM_BYTE( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADC_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_ADC_AC_IM_WORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADC_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_ADC_AC_IM_DWORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADC_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_ADC_AC_IM_QWORD( io, imm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADC_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_ADD_MM_RG                            0x00000000
#define X86IM_GEN_CODE_ADD_R2_R1                            0x0000C000
#define X86IM_GEN_CODE_ADD_RG_MM                            0x00000002
#define X86IM_GEN_CODE_ADD_R1_R2                            0x0000C002
#define X86IM_GEN_CODE_ADD_MM_IM                            0x00000080
#define X86IM_GEN_CODE_ADD_RG_IM                            0x0000C080
#define X86IM_GEN_CODE_ADD_AC_IM                            0x00000004

#define X86IM_GEN_ADD_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_ADD_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_ADD_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_ADD_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_ADD_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADD_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_ADD_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADD_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_ADD_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADD_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_ADD_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADD_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_ADD_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADD_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_ADD_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADD_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_ADD_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADD_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_ADD_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADD_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_ADD_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADD_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_ADD_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADD_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_ADD_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADD_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_ADD_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADD_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_ADD_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm ) 
#define X86IM_GEN_ADD_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm )
#define X86IM_GEN_ADD_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm )
#define X86IM_GEN_ADD_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm )

#define X86IM_GEN_ADD_MM_IM_SBYTE( io, mode, mm, imm8 )     x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ADD_MM_IM_SWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ADD_MM_IM_SDWORD( io, mode, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ADD_MM_IM_SQWORD( io, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_ADD_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ADD_RG_IM_WORD( io, mode, rg, imm16 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm16 )
#define X86IM_GEN_ADD_RG_IM_DWORD( io, mode, rg, imm32 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )
#define X86IM_GEN_ADD_RG_IM_QWORD( io, rg, imm32 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )

#define X86IM_GEN_ADD_RG_IM_SBYTE( io, mode, rg8, imm8 )    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_ADD_RG_IM_SWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ADD_RG_IM_SDWORD( io, mode, rg, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ADD_RG_IM_SQWORD( io, rg, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_ADD_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  

#define X86IM_GEN_ADD_AC_IM_BYTE( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ADD_AC_IM, 0, 0, 0, imm )     
#define X86IM_GEN_ADD_AC_IM_WORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ADD_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_ADD_AC_IM_DWORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ADD_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_ADD_AC_IM_QWORD( io, imm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ADD_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_AND_MM_RG                            0x00000020
#define X86IM_GEN_CODE_AND_R2_R1                            0x0000C020
#define X86IM_GEN_CODE_AND_RG_MM                            0x00000022
#define X86IM_GEN_CODE_AND_R1_R2                            0x0000C022
#define X86IM_GEN_CODE_AND_MM_IM                            0x00002080
#define X86IM_GEN_CODE_AND_RG_IM                            0x0000E080
#define X86IM_GEN_CODE_AND_AC_IM                            0x00000024
       
#define X86IM_GEN_AND_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_AND_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_AND_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_AND_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_AND_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_AND_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_AND_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_AND_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_AND_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_AND_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_AND_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_AND_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_AND_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_AND_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_AND_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_AND_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_AND_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_AND_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_AND_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_AND_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_AND_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_AND_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_AND_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_AND_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_AND_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_AND_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_AND_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_AND_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_AND_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_AND_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_AND_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_AND_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_AND_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm ) 
#define X86IM_GEN_AND_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm )
#define X86IM_GEN_AND_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm )
#define X86IM_GEN_AND_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm )

#define X86IM_GEN_AND_MM_IM_SBYTE( io, mode, mm, imm8 )     x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_AND_MM_IM_SWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_AND_MM_IM_SDWORD( io, mode, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_AND_MM_IM_SQWORD( io, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_AND_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_AND_RG_IM_WORD( io, mode, rg, imm16 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm16 )
#define X86IM_GEN_AND_RG_IM_DWORD( io, mode, rg, imm32 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )
#define X86IM_GEN_AND_RG_IM_QWORD( io, rg, imm32 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )

#define X86IM_GEN_AND_RG_IM_SBYTE( io, mode, rg8, imm8 )    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_AND_RG_IM_SWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  
#define X86IM_GEN_AND_RG_IM_SDWORD( io, mode, rg, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_AND_RG_IM_SQWORD( io, rg, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_AND_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  

#define X86IM_GEN_AND_AC_IM_BYTE( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_AND_AC_IM, 0, 0, 0, imm )     
#define X86IM_GEN_AND_AC_IM_WORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_AND_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_AND_AC_IM_DWORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_AND_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_AND_AC_IM_QWORD( io, imm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_AND_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_ARPL_MM_RG                           0x00000063
#define X86IM_GEN_CODE_ARPL_R1_R2                           0x0000C063

#define X86IM_GEN_ARPL_MM_RG( io, mm, rg )                  x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_ARPL_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_ARPL_R1_R2( io, r1, r2 )                  x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_ARPL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_MOVSXD_RG_MM( io, rg, mm )                x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_ARPL_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_MOVSXD_R1_R2( io, r1, r2 )                x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_ARPL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_BSF_RG_MM                            0x0000BC0F
#define X86IM_GEN_CODE_BSF_R1_R2                            0x00C0BC0F

#define X86IM_GEN_BSF_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BSF_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_BSF_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BSF_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_BSF_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BSF_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_BSF_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BSF_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BSF_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BSF_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BSF_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BSF_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_BSR_RG_MM                            0x0000BD0F
#define X86IM_GEN_CODE_BSR_R1_R2                            0x00C0BD0F

#define X86IM_GEN_BSR_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BSR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_BSR_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BSR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_BSR_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BSR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_BSR_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BSR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BSR_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BSR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BSR_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BSR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_BT_MM_IM                             0x0020BA0F
#define X86IM_GEN_CODE_BT_RG_IM                             0x00E0BA0F
#define X86IM_GEN_CODE_BT_MM_RG                             0x0000A30F
#define X86IM_GEN_CODE_BT_R1_R2                             0x00C0A30F

#define X86IM_GEN_BT_MM_IM_WORD( io, mode, mm, imm8 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BT_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BT_MM_IM_DWORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BT_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BT_MM_IM_QWORD( io, mm, imm8 )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BT_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_BT_RG_IM_WORD( io, mode, rg, imm8 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BT_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BT_RG_IM_DWORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BT_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BT_RG_IM_QWORD( io, rg, imm8 )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BT_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_BT_MM_RG_WORD( io, mode, mm, rg )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BT_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BT_MM_RG_DWORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BT_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BT_MM_RG_QWORD( io, mm, rg )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BT_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_BT_R1_R2_WORD( io, mode, r1, r2 )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BT_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BT_R1_R2_DWORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BT_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BT_R1_R2_QWORD( io, r1, r2 )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BT_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_BTC_MM_IM                            0x0038BA0F
#define X86IM_GEN_CODE_BTC_RG_IM                            0x00F8BA0F
#define X86IM_GEN_CODE_BTC_MM_RG                            0x0000BB0F
#define X86IM_GEN_CODE_BTC_R1_R2                            0x00C0BB0F

#define X86IM_GEN_BTC_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTC_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BTC_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTC_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BTC_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTC_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_BTC_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BTC_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BTC_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTC_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_BTC_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTC_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 ) 
#define X86IM_GEN_BTC_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTC_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BTC_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTC_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_BTC_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTC_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BTC_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTC_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BTC_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTC_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_BTR_MM_IM                            0x0030BA0F
#define X86IM_GEN_CODE_BTR_RG_IM                            0x00F0BA0F
#define X86IM_GEN_CODE_BTR_MM_RG                            0x0000B30F
#define X86IM_GEN_CODE_BTR_R1_R2                            0x00C0B30F

#define X86IM_GEN_BTR_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BTR_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BTR_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTR_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_BTR_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BTR_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BTR_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_BTR_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BTR_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BTR_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_BTR_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BTR_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BTR_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_BTS_MM_IM                            0x0028BA0F
#define X86IM_GEN_CODE_BTS_RG_IM                            0x00E8BA0F
#define X86IM_GEN_CODE_BTS_MM_RG                            0x0000AB0F
#define X86IM_GEN_CODE_BTS_R1_R2                            0x00C0AB0F

#define X86IM_GEN_BTS_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTS_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BTS_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTS_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_BTS_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTS_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_BTS_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTS_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BTS_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTS_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_BTS_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTS_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_BTS_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTS_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BTS_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTS_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_BTS_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTS_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_BTS_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_BTS_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BTS_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_BTS_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_BTS_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_BTS_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_CALL_N_R                             0x000000E8
#define X86IM_GEN_CODE_CALL_N_AI_RG                         0x0000D0FF
#define X86IM_GEN_CODE_CALL_N_AI_M                          0x000010FF
#define X86IM_GEN_CODE_CALL_F_A                             0x0000009A
#define X86IM_GEN_CODE_CALL_F_AI_MM                         0x000018FF

#define X86IM_GEN_CALL_N_REL16( io, rel16 )                 x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CALL_N_R, 0, 0, 0, rel16 )
#define X86IM_GEN_CALL_N_REL32( io, mode, rel32 )           x86im_gen( io, mode, X86IM_GEN_CODE_CALL_N_R, 0, 0, 0, rel32 )

#define X86IM_GEN_CALL_N_AI_RG16( io, rg16 )                x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CALL_N_AI_RG, rg16, 0, 0, 0 )
#define X86IM_GEN_CALL_N_AI_RG32( io, rg32 )                x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_CALL_N_AI_RG, rg32, 0, 0, 0 )
#define X86IM_GEN_CALL_N_AI_RG64( io, rg64 )                x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_CALL_N_AI_RG, rg64, 0, 0, 0 )

#define X86IM_GEN_CALL_N_AI_MM16( io, mm16 )                x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CALL_N_AI_M, 0, mm16, 0 )
#define X86IM_GEN_CALL_N_AI_MM32( io, mm32 )                x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_CALL_N_AI_M, 0, mm32, 0 )
#define X86IM_GEN_CALL_N_AI_MM64( io, mm64 )                x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_CALL_N_AI_M, 0, mm64, 0 )

#define X86IM_GEN_CALL_F_A16( io, off16, sel )              x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CALL_F_A, 0, 0, sel, off16 )
#define X86IM_GEN_CALL_F_A32( io, off32, sel )              x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_CALL_F_A, 0, 0, sel, off32 )

#define X86IM_GEN_CALL_F_AI_MM16( io, mode, mm16 )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CALL_F_AI_MM, 0, mm16, 0 )
#define X86IM_GEN_CALL_F_AI_MM32( io, mode, mm32 )          x86im_gen( io, mode, X86IM_GEN_CODE_CALL_F_AI_MM, 0, mm32, 0 )
#define X86IM_GEN_CALL_F_AI_MM64( io, mm64 )                x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_CALL_F_AI_MM, 0, mm64, 0 )

#define X86IM_GEN_CODE_CMP_MM_RG                            0x00000038
#define X86IM_GEN_CODE_CMP_R2_R1                            0x0000C038
#define X86IM_GEN_CODE_CMP_RG_MM                            0x0000003A
#define X86IM_GEN_CODE_CMP_R1_R2                            0x0000C03A
#define X86IM_GEN_CODE_CMP_RG_IM                            0x0000F880
#define X86IM_GEN_CODE_CMP_MM_IM                            0x00003880
#define X86IM_GEN_CODE_CMP_RG_IM                            0x0000F880
#define X86IM_GEN_CODE_CMP_AC_IM                            0x0000003C

#define X86IM_GEN_CMP_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMP_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_CMP_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMP_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_CMP_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMP_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_CMP_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMP_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_CMP_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMP_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMP_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMP_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMP_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMP_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMP_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMP_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CMP_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMP_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_CMP_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMP_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_CMP_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMP_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_CMP_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMP_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CMP_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMP_R2_R1, X86IM_GEN_R1_R2( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_CMP_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMP_R2_R1, X86IM_GEN_R1_R2( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_CMP_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMP_R2_R1, X86IM_GEN_R1_R2( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_CMP_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMP_R2_R1, X86IM_GEN_R1_R2( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_CMP_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm )
#define X86IM_GEN_CMP_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm )
#define X86IM_GEN_CMP_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm )
#define X86IM_GEN_CMP_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm )

#define X86IM_GEN_CMP_MM_IM_SBYTE( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_CMP_MM_IM_SWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_CMP_MM_IM_SDWORD( io, mode, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_CMP_MM_IM_SQWORD( io, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_CMP_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_CMP_RG_IM_WORD( io, mode, rg, imm16 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm16 )
#define X86IM_GEN_CMP_RG_IM_DWORD( io, mode, rg, imm32 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )
#define X86IM_GEN_CMP_RG_IM_QWORD( io, rg, imm32 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )

#define X86IM_GEN_CMP_RG_IM_SBYTE( io, rg8, imm8 )          x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_CMP_RG_IM_SWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_CMP_RG_IM_SDWORD( io, mode, rg, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_CMP_RG_IM_SQWORD( io, rg, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_CMP_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CMP_AC_IM_BYTE( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMP_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_CMP_AC_IM_WORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMP_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_CMP_AC_IM_DWORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMP_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_CMP_AC_IM_QWORD( io, imm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMP_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_CMPXCHG_MM_RG                        0x0000B00F
#define X86IM_GEN_CODE_CMPXCHG_R1_R2                        0x00C0B00F
    
#define X86IM_GEN_CMPXCHG_MM_RG_BYTE( io, mode, mm, rg )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMPXCHG_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_CMPXCHG_MM_RG_WORD( io, mode, mm, rg )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMPXCHG_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_CMPXCHG_MM_RG_DWORD( io, mode, mm, rg )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMPXCHG_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_CMPXCHG_MM_RG_QWORD( io, mm, rg )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMPXCHG_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_CMPXCHG_R1_R2_BYTE( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_CMPXCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMPXCHG_R1_R2_WORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMPXCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMPXCHG_R1_R2_DWORD( io, mode, r1, r2 )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMPXCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMPXCHG_R1_R2_QWORD( io, r1, r2 )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMPXCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_DEC_MM                               0x000008FE
#define X86IM_GEN_CODE_DEC_RG1                              0x0000C8FE
#define X86IM_GEN_CODE_DEC_RG2                              0x00000048

#define X86IM_GEN_DEC_MM_BYTE( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_DEC_MM, 0, mm, 0 )
#define X86IM_GEN_DEC_MM_WORD( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_DEC_MM, 0, mm, 0 )
#define X86IM_GEN_DEC_MM_DWORD( io, mode, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_DEC_MM, 0, mm, 0 )
#define X86IM_GEN_DEC_MM_QWORD( io, mm )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_DEC_MM, 0, mm, 0 )

#define X86IM_GEN_DEC_RG1_BYTE( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_DEC_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_DEC_RG1_WORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_DEC_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_DEC_RG1_DWORD( io, mode, rg)              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_DEC_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_DEC_RG1_QWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_DEC_RG1, rg, 0, 0, 0 )

#define X86IM_GEN_DEC_RG2_WORD( io, rg )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_DEC_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_DEC_RG2_DWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_DEC_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_DIV_AC_MM                            0x000030F6
#define X86IM_GEN_CODE_DIV_AC_RG                            0x0000F0F6

#define X86IM_GEN_DIV_AC_MM_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_DIV_AC_MM, 0, mm, 0 )
#define X86IM_GEN_DIV_AC_MM_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_DIV_AC_MM, 0, mm, 0 )
#define X86IM_GEN_DIV_AC_MM_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_DIV_AC_MM, 0, mm, 0 )
#define X86IM_GEN_DIV_AC_MM_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_DIV_AC_MM, 0, mm, 0 )

#define X86IM_GEN_DIV_AC_RG_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_DIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_DIV_AC_RG_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_DIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_DIV_AC_RG_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_DIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_DIV_AC_RG_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_DIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_IDIV_AC_MM                           0x000038F6
#define X86IM_GEN_CODE_IDIV_AC_RG                           0x0000F8F6

#define X86IM_GEN_IDIV_AC_MM_BYTE( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_IDIV_AC_MM, 0, mm, 0 )
#define X86IM_GEN_IDIV_AC_MM_WORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IDIV_AC_MM, 0, mm, 0 )
#define X86IM_GEN_IDIV_AC_MM_DWORD( io, mode, mm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IDIV_AC_MM, 0, mm, 0 )
#define X86IM_GEN_IDIV_AC_MM_QWORD( io, mm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IDIV_AC_MM, 0, mm, 0 )

#define X86IM_GEN_IDIV_AC_RG_BYTE( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_IDIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_IDIV_AC_RG_WORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IDIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_IDIV_AC_RG_DWORD( io, mode, rg )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IDIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_IDIV_AC_RG_QWORD( io, rg )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IDIV_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_IMUL_AC_MM                               0x000028F6
#define X86IM_GEN_CODE_IMUL_AC_RG                               0x0000E8F6
#define X86IM_GEN_CODE_IMUL_RG_MM                               0x0000AF0F
#define X86IM_GEN_CODE_IMUL_R1_R2                               0x00C0AF0F
#define X86IM_GEN_CODE_IMUL_RG_MM_IM                            0x00000069
#define X86IM_GEN_CODE_IMUL_R1_R2_IM                            0x0000C069
#define X86IM_GEN_CODE_IMUL_RG_IM                               X86IM_GEN_CODE_IMUL_R1_R2_IM

#define X86IM_GEN_IMUL_AC_MM_BYTE( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_IMUL_AC_MM, 0, mm, 0 )
#define X86IM_GEN_IMUL_AC_MM_WORD( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IMUL_AC_MM, 0, mm, 0 )
#define X86IM_GEN_IMUL_AC_MM_DWORD( io, mode, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IMUL_AC_MM, 0, mm, 0 )
#define X86IM_GEN_IMUL_AC_MM_QWORD( io, mm )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IMUL_AC_MM,  0, mm, 0 )

#define X86IM_GEN_IMUL_AC_RG_BYTE( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_IMUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_IMUL_AC_RG_WORD( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IMUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_IMUL_AC_RG_DWORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IMUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_IMUL_AC_RG_QWORD( io, rg )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IMUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_IMUL_RG_MM_WORD( io, mode, rg, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IMUL_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_IMUL_RG_MM_DWORD( io, mode, rg, mm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IMUL_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_IMUL_RG_MM_QWORD( io, rg, mm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IMUL_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_IMUL_R1_R2_WORD( io, mode, r1, r2 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IMUL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_IMUL_R1_R2_DWORD( io, mode, r1, r2 )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IMUL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_IMUL_R1_R2_QWORD( io, r1, r2 )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IMUL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_IMUL_RG_MM_IM_WORD( io, mode, rg, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IMUL_RG_MM_IM, X86IM_GEN_RG_MM( rg ), mm, imm )
#define X86IM_GEN_IMUL_RG_MM_IM_DWORD( io, mode, rg, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IMUL_RG_MM_IM, X86IM_GEN_RG_MM( rg ), mm, imm )
#define X86IM_GEN_IMUL_RG_MM_IM_QWORD( io, rg, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IMUL_RG_MM_IM, X86IM_GEN_RG_MM( rg ), mm, imm )

#define X86IM_GEN_IMUL_RG_MM_IM_SWORD( io, mode, rg, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_RG_MM_IM, X86IM_GEN_RG_MM( rg ), mm, imm8 )
#define X86IM_GEN_IMUL_RG_MM_IM_SDWORD( io, mode, rg, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_RG_MM_IM, X86IM_GEN_RG_MM( rg ), mm, imm8 )
#define X86IM_GEN_IMUL_RG_MM_IM_SQWORD( io, rg, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_RG_MM_IM, X86IM_GEN_RG_MM( rg ), mm, imm8 )

#define X86IM_GEN_IMUL_R1_R2_IM_WORD( io, mode, r1, r2, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IMUL_R1_R2_IM, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, imm )
#define X86IM_GEN_IMUL_R1_R2_IM_DWORD( io, mode, r1, r2, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IMUL_R1_R2_IM, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, imm )
#define X86IM_GEN_IMUL_R1_R2_IM_QWORD( io, r1, r2, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IMUL_R1_R2_IM, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, imm )

#define X86IM_GEN_IMUL_R1_R2_IM_SWORD( io, mode, r1, r2, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_R1_R2_IM, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, imm8 )
#define X86IM_GEN_IMUL_R1_R2_IM_SDWORD( io, mode, r1, r2, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_R1_R2_IM, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, imm8 )
#define X86IM_GEN_IMUL_R1_R2_IM_SQWORD( io, r1, r2, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_R1_R2_IM, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, imm8 )

#define X86IM_GEN_IMUL_RG_IM_WORD( io, mode, rg, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IMUL_RG_IM, X86IM_GEN_R1_R2( rg, rg ), 0, 0, imm )
#define X86IM_GEN_IMUL_RG_IM_DWORD( io, mode, rg, imm )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IMUL_RG_IM, X86IM_GEN_R1_R2( rg, rg ), 0, 0, imm )
#define X86IM_GEN_IMUL_RG_IM_QWORD( io, rg, imm )               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IMUL_RG_IM, X86IM_GEN_R1_R2( rg, rg ), 0, 0, imm )

#define X86IM_GEN_IMUL_RG_IM_SWORD( io, mode, rg, imm8 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_RG_IM, X86IM_GEN_R1_R2( rg, rg ), 0, 0, imm8 )
#define X86IM_GEN_IMUL_RG_IM_SDWORD( io, mode, rg, imm8 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_RG_IM, X86IM_GEN_R1_R2( rg, rg ), 0, 0, imm8 )
#define X86IM_GEN_IMUL_RG_IM_SQWORD( io, rg, imm8 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_IMUL_RG_IM, X86IM_GEN_R1_R2( rg, rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_IN_AC_IM                             0x000000E4
#define X86IM_GEN_CODE_IN_AC_RG                             0x000000EC

#define X86IM_GEN_IN_AC_IM_BYTE( io, mode, imm8 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_IN_AC_IM, 0, 0, 0, imm8 )          
#define X86IM_GEN_IN_AC_IM_WORD( io, mode, imm8 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IN_AC_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_IN_AC_IM_DWORD( io, mode, imm8 )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IN_AC_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_IN_AC_IM_QWORD( io, imm8 )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IN_AC_IM, 0, 0, 0, imm8 )

#define X86IM_GEN_IN_AC_DX_BYTE( io, mode )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_IN_AC_RG, 0, 0, 0, 0 )
#define X86IM_GEN_IN_AC_DX_WORD( io, mode )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_IN_AC_RG, 0, 0, 0, 0 )
#define X86IM_GEN_IN_AC_DX_DWORD( io, mode )                x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_IN_AC_RG, 0, 0, 0, 0 )
#define X86IM_GEN_IN_AC_DX_QWORD( io )                      x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_IN_AC_RG, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_INC_MM                               0x000000FE
#define X86IM_GEN_CODE_INC_RG1                              0x0000C0FE
#define X86IM_GEN_CODE_INC_RG2                              0x00000040

#define X86IM_GEN_INC_MM_BYTE( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_INC_MM, 0, mm, 0 )
#define X86IM_GEN_INC_MM_WORD( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_INC_MM, 0, mm, 0 )
#define X86IM_GEN_INC_MM_DWORD( io, mode, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_INC_MM, 0, mm, 0 )
#define X86IM_GEN_INC_MM_QWORD( io, mm )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_INC_MM, 0, mm, 0 )

#define X86IM_GEN_INC_RG1_BYTE( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_INC_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_INC_RG1_WORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_INC_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_INC_RG1_DWORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_INC_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_INC_RG1_QWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_INC_RG1, rg, 0, 0, 0 )

#define X86IM_GEN_INC_RG2_WORD( io, rg )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_INC_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_INC_RG2_DWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_INC_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_JCC_SHORT                            0x00000070
#define X86IM_GEN_CODE_JCC_NEAR                             0x0000800F

#define X86IM_GEN_JA_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_A ), 0, 0, rel8 )
#define X86IM_GEN_JAE_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_AE ), 0, 0, rel8 )
#define X86IM_GEN_JB_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_B ), 0, 0, rel8 )
#define X86IM_GEN_JBE_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_BE ), 0, 0, rel8 )
#define X86IM_GEN_JC_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_C ), 0, 0, rel8 )
#define X86IM_GEN_JE_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_E ), 0, 0, rel8 )
#define X86IM_GEN_JG_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_G ), 0, 0, rel8 )
#define X86IM_GEN_JGE_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_GE ), 0, 0, rel8 )
#define X86IM_GEN_JL_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_L ), 0, 0, rel8 )
#define X86IM_GEN_JLE_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_LE ), 0, 0, rel8 )
#define X86IM_GEN_JNA_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NA ), 0, 0, rel8 )    
#define X86IM_GEN_JNAE_SHORT( io, mode, rel8 )              x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NAE ), 0, 0, rel8 )
#define X86IM_GEN_JNB_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NB ), 0, 0, rel8 )
#define X86IM_GEN_JNBE_SHORT( io, mode, rel8 )              x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NBE ), 0, 0, rel8 )
#define X86IM_GEN_JNC_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NC ), 0, 0, rel8 )
#define X86IM_GEN_JNE_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NE ), 0, 0, rel8 )
#define X86IM_GEN_JNG_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NG ), 0, 0, rel8 )
#define X86IM_GEN_JNGE_SHORT( io, mode, rel8 )              x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NGE ), 0, 0, rel8 )
#define X86IM_GEN_JNL_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NL ), 0, 0, rel8 )
#define X86IM_GEN_JNLE_SHORT( io, mode, rel8 )              x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NLE ), 0, 0, rel8 )
#define X86IM_GEN_JNO_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NO ), 0, 0, rel8 )
#define X86IM_GEN_JNP_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NP ), 0, 0, rel8 )
#define X86IM_GEN_JNS_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NS ), 0, 0, rel8 )
#define X86IM_GEN_JNZ_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_NZ ), 0, 0, rel8 )
#define X86IM_GEN_JO_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_O ), 0, 0, rel8 )
#define X86IM_GEN_JP_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_P ), 0, 0, rel8 )
#define X86IM_GEN_JPE_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_PE ), 0, 0, rel8 )
#define X86IM_GEN_JPO_SHORT( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_PO ), 0, 0, rel8 )
#define X86IM_GEN_JS_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_S ), 0, 0, rel8 )
#define X86IM_GEN_JZ_SHORT( io, mode, rel8 )                x86im_gen( io, mode, X86IM_GEN_CODE_JCC_SHORT, X86IM_GEN_TTTN( X86IM_IO_TN_Z ), 0, 0, rel8 )

#define X86IM_GEN_JA_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_A ), 0, 0, rel16 )
#define X86IM_GEN_JAE_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_AE ), 0, 0, rel16 )
#define X86IM_GEN_JB_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_B ), 0, 0, rel16 )
#define X86IM_GEN_JBE_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_BE ), 0, 0, rel16 )
#define X86IM_GEN_JC_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_C ), 0, 0, rel16 )
#define X86IM_GEN_JE_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_E ), 0, 0, rel16 )
#define X86IM_GEN_JG_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_G ), 0, 0, rel16 )
#define X86IM_GEN_JGE_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_GE ), 0, 0, rel16 )
#define X86IM_GEN_JL_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_L ), 0, 0, rel16 )    
#define X86IM_GEN_JLE_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_LE ), 0, 0, rel16 )
#define X86IM_GEN_JNA_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NA ), 0, 0, rel16 )
#define X86IM_GEN_JNAE_NEAR16( io, rel16 )                  x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NAE ), 0, 0, rel16 )
#define X86IM_GEN_JNB_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NB ), 0, 0, rel16 )
#define X86IM_GEN_JNBE_NEAR16( io, rel16 )                  x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NBE ), 0, 0, rel16 )
#define X86IM_GEN_JNC_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NC ), 0, 0, rel16 )
#define X86IM_GEN_JNE_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NE ), 0, 0, rel16 )
#define X86IM_GEN_JNG_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NG ), 0, 0, rel16 )
#define X86IM_GEN_JNGE_NEAR16( io, rel16 )                  x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NGE ), 0, 0, rel16 )
#define X86IM_GEN_JNL_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NL ), 0, 0, rel16 )
#define X86IM_GEN_JNLE_NEAR16( io, rel16 )                  x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NLE ), 0, 0, rel16 )
#define X86IM_GEN_JNO_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NO ), 0, 0, rel16 )
#define X86IM_GEN_JNP_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NP ), 0, 0, rel16 )
#define X86IM_GEN_JNS_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NS ), 0, 0, rel16 )
#define X86IM_GEN_JNZ_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NZ ), 0, 0, rel16 )
#define X86IM_GEN_JO_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_O ), 0, 0, rel16 )
#define X86IM_GEN_JP_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_P ), 0, 0, rel16 )
#define X86IM_GEN_JPE_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_PE ), 0, 0, rel16 )
#define X86IM_GEN_JPO_NEAR16( io, rel16 )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_PO ), 0, 0, rel16 )
#define X86IM_GEN_JS_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_S ), 0, 0, rel16 )
#define X86IM_GEN_JZ_NEAR16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_Z ), 0, 0, rel16 )

#define X86IM_GEN_JA( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_A ), 0, 0, rel32 )
#define X86IM_GEN_JAE( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_AE ), 0, 0, rel32 )
#define X86IM_GEN_JB( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_B ), 0, 0, rel32 )
#define X86IM_GEN_JBE( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_BE ), 0, 0, rel32 )
#define X86IM_GEN_JC( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_C ), 0, 0, rel32 )
#define X86IM_GEN_JE( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_E ), 0, 0, rel32 )
#define X86IM_GEN_JG( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_G ), 0, 0, rel32 )
#define X86IM_GEN_JGE( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_GE ), 0, 0, rel32 )
#define X86IM_GEN_JL( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_L ), 0, 0, rel32 )
#define X86IM_GEN_JLE( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_LE ), 0, 0, rel32 )
#define X86IM_GEN_JNA( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NA ), 0, 0, rel32 )
#define X86IM_GEN_JNAE( io, mode, rel32 )                   x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NAE ), 0, 0, rel32 )
#define X86IM_GEN_JNB( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NB ), 0, 0, rel32 )       
#define X86IM_GEN_JNBE( io, mode, rel32 )                   x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NBE ), 0, 0, rel32 )
#define X86IM_GEN_JNC( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NC ), 0, 0, rel32 )
#define X86IM_GEN_JNE( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NE ), 0, 0, rel32 )
#define X86IM_GEN_JNG( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NG ), 0, 0, rel32 )
#define X86IM_GEN_JNGE( io, mode, rel32 )                   x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NGE ), 0, 0, rel32 )
#define X86IM_GEN_JNL( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NL ), 0, 0, rel32 )
#define X86IM_GEN_JNLE( io, mode, rel32 )                   x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NLE ), 0, 0, rel32 )
#define X86IM_GEN_JNO( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NO ), 0, 0, rel32 )
#define X86IM_GEN_JNP( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NP ), 0, 0, rel32 )
#define X86IM_GEN_JNS( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NS ), 0, 0, rel32 )
#define X86IM_GEN_JNZ( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_NZ ), 0, 0, rel32 )      
#define X86IM_GEN_JO( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_O ), 0, 0, rel32 )
#define X86IM_GEN_JP( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_P ), 0, 0, rel32 )      
#define X86IM_GEN_JPE( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_PE ), 0, 0, rel32 )
#define X86IM_GEN_JPO( io, mode, rel32 )                    x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_PO ), 0, 0, rel32 )
#define X86IM_GEN_JS( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_S ), 0, 0, rel32 )
#define X86IM_GEN_JZ( io, mode, rel32 )                     x86im_gen( io, mode, X86IM_GEN_CODE_JCC_NEAR, X86IM_GEN_TTTN( X86IM_IO_TN_Z ), 0, 0, rel32 )

#define X86IM_GEN_CODE_JMP_N_R_S                            0x000000EB
#define X86IM_GEN_CODE_JMP_N_R                              0x000000E9
#define X86IM_GEN_CODE_JMP_N_AI_RG                          0x0000E0FF
#define X86IM_GEN_CODE_JMP_N_AI_MM                          0x000020FF
#define X86IM_GEN_CODE_JMP_F_A                              0x000000EA
#define X86IM_GEN_CODE_JMP_F_AI_MM                          0x000028FF

#define X86IM_GEN_JMP_N_R_S( io, mode, rel8 )               x86im_gen( io, mode, X86IM_GEN_CODE_JMP_N_R_S, 0, 0, 0, rel8 )

#define X86IM_GEN_JMP_N_R16( io, rel16 )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JMP_N_R, 0, 0, 0, rel16 )
#define X86IM_GEN_JMP_N_R32( io, mode, rel32 )              x86im_gen( io, mode, X86IM_GEN_CODE_JMP_N_R, 0, 0, 0, rel32 )

#define X86IM_GEN_JMP_N_AI_RG_WORD( io, mode, rg )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JMP_N_AI_RG, rg, 0, 0, 0 )
#define X86IM_GEN_JMP_N_AI_RG_DWORD( io, rg )               x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_JMP_N_AI_RG, rg, 0, 0, 0 )
#define X86IM_GEN_JMP_N_AI_RG_QWORD( io, rg )               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_JMP_N_AI_RG, rg, 0, 0, 0 )

#define X86IM_GEN_JMP_N_AI_MM_WORD( io, mode, mm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JMP_N_AI_MM, 0, mm, 0 )
#define X86IM_GEN_JMP_N_AI_MM_DWORD( io, mm )               x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_JMP_N_AI_MM, 0, mm, 0 )
#define X86IM_GEN_JMP_N_AI_MM_QWORD( io, mm )               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_JMP_N_AI_MM, 0, mm, 0 )

#define X86IM_GEN_JMP_F_A_WORD( io, addr, sel )             x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JMP_F_A, 0, 0, sel, addr ) 
#define X86IM_GEN_JMP_F_A_DWORD( io, addr, sel )            x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_JMP_F_A, 0, 0, sel, addr )

#define X86IM_GEN_JMP_F_AI_MM_WORD( io, mode, mm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_JMP_F_AI_MM, 0, mm, 0 )
#define X86IM_GEN_JMP_F_AI_MM_DWORD( io, mode, mm )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_JMP_F_AI_MM, 0, mm, 0 )
#define X86IM_GEN_JMP_F_AI_MM_QWORD( io, mm )               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_JMP_F_AI_MM, 0, mm, 0 )

#define X86IM_GEN_CODE_LAR_RG_MM                            0x0000020F
#define X86IM_GEN_CODE_LAR_R1_R2                            0x00C0020F

#define X86IM_GEN_LAR_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LAR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LAR_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LAR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LAR_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LAR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_LAR_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LAR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_LAR_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LAR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_LAR_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LAR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_LLDT_MM                              0x0010000F
#define X86IM_GEN_CODE_LLDT_RG                              0x00D0000F

#define X86IM_GEN_LLDT_MM( io, mode, mm )                   x86im_gen( io, mode, X86IM_GEN_CODE_LLDT_MM, 0, mm, 0 )
#define X86IM_GEN_LLDT_RG( io, mode, rg )                   x86im_gen( io, mode, X86IM_GEN_CODE_LLDT_RG, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_LMSW_MM                              0x0030010F
#define X86IM_GEN_CODE_LMSW_RG                              0x00F0010F

#define X86IM_GEN_LMSW_MM( io, mode, mm )                   x86im_gen( io, mode, X86IM_GEN_CODE_LMSW_MM, 0, mm, 0 )
#define X86IM_GEN_LMSW_RG( io, mode, rg )                   x86im_gen( io, mode, X86IM_GEN_CODE_LMSW_RG, rg, 0, 0, 0)

#define X86IM_GEN_CODE_LSL_RG_MM                            0x0000030F
#define X86IM_GEN_CODE_LSL_R1_R2                            0x00C0030F

#define X86IM_GEN_LSL_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LSL_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LSL_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LSL_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_LSL_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LSL_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_LSL_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_LSL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_LSL_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_LSL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_LSL_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_LSL_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_LTR_MM                               0x0018000F
#define X86IM_GEN_CODE_LTR_RG                               0x00D8000F

#define X86IM_GEN_LTR_MM( io, mode, mm )                    x86im_gen( io, mode, X86IM_GEN_CODE_LTR_MM, 0, mm, 0 )
#define X86IM_GEN_LTR_RG( io, mode, rg )                    x86im_gen( io, mode, X86IM_GEN_CODE_LTR_RG, rg, 0, 0, 0 )                         

#define X86IM_GEN_CODE_MOV_MM_RG                            0x00000088
#define X86IM_GEN_CODE_MOV_R2_R1                            0x0000C088
#define X86IM_GEN_CODE_MOV_RG_MM                            0x0000008A
#define X86IM_GEN_CODE_MOV_R1_R2                            0x0000C08A
#define X86IM_GEN_CODE_MOV_MM_IM                            0x000000C6
#define X86IM_GEN_CODE_MOV_RG_IM                            0x0000C0C6
#define X86IM_GEN_CODE_MOV_AC_IM                            0x000000B0
#define X86IM_GEN_CODE_MOV_AC_MM                            0x000000A0
#define X86IM_GEN_CODE_MOV_MM_AC                            0x000000A2
#define X86IM_GEN_CODE_MOV_CRX_RG                           0x00C0220F
#define X86IM_GEN_CODE_MOV_RG_CRX                           0x00C0200F
#define X86IM_GEN_CODE_MOV_DRX_RG                           0x00C0230F
#define X86IM_GEN_CODE_MOV_RG_DRX                           0x00C0210F
#define X86IM_GEN_CODE_MOV_SRX_MM                           0x0000008E
#define X86IM_GEN_CODE_MOV_MM_SRX                           0x0000008C
#define X86IM_GEN_CODE_MOV_SRX_RG                           0x0000C08E
#define X86IM_GEN_CODE_MOV_RG_SRX                           0x0000C08C

#define X86IM_GEN_MOV_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_MOV_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_MOV_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_MOV_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_MOV_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_MOV_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_MOV_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_MOV_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_MOV_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOV_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOV_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOV_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_MOV_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOV_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOV_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOV_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_MOV_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_MM_IM, 0, mm, imm )
#define X86IM_GEN_MOV_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_MM_IM, 0, mm, imm )
#define X86IM_GEN_MOV_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_MM_IM, 0, mm, imm )
#define X86IM_GEN_MOV_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_MM_IM, 0, mm, imm )

#define X86IM_GEN_MOV_RG_IM_BYTE( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_MOV_RG_IM_WORD( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_MOV_RG_IM_DWORD( io, mode, rg, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_MOV_RG_IM_QWORD( io, rg, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm ) // rg64,imm32

#define X86IM_GEN_MOV_AC_IM_BYTE( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_AC_IM, X86IM_GEN_OP_RG( rg ), 0, 0, imm )
#define X86IM_GEN_MOV_AC_IM_WORD( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_AC_IM, X86IM_GEN_OP_RG( rg ), 0, 0, imm )
#define X86IM_GEN_MOV_AC_IM_DWORD( io, mode, rg, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_AC_IM, X86IM_GEN_OP_RG( rg ), 0, 0, imm )
#define X86IM_GEN_MOV_AC_IM_QWORD( io, rg, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_AC_IM, X86IM_GEN_OP_RG( rg ), 0, 0, imm ) // r64,imm64

#define X86IM_GEN_MOV_AC_MM_BYTE( io, mode, mof32 )			x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_AC_MM, 0, 0, mof32, 0 )
#define X86IM_GEN_MOV_AC_MM_WORD( io, mode, mof32 )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_AC_MM, 0, 0, mof32, 0 )
#define X86IM_GEN_MOV_AC_MM_DWORD( io, mode, mof32 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_AC_MM, 0, 0, mof32, 0 )
#define X86IM_GEN_MOV_AC_MM_QWORD( io, mof64 )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_AC_MM, 0, 0, mof64, 0 )

#define X86IM_GEN_MOV_MM_AC_BYTE( io, mode, mof32 )			x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MOV_MM_AC, 0, 0, mof32, 0 )
#define X86IM_GEN_MOV_MM_AC_WORD( io, mode, mof32 )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_MM_AC, 0, 0, mof32, 0 )
#define X86IM_GEN_MOV_MM_AC_DWORD( io, mode, mof32 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_MM_AC, 0, 0, mof32, 0 )
#define X86IM_GEN_MOV_MM_AC_QWORD( io, mof64 )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_MM_AC, 0, 0, mof64, 0 )

#define X86IM_GEN_MOV_CRX_RG( io, mode, crx, rg )           x86im_gen( io, mode, X86IM_GEN_CODE_MOV_CRX_RG, X86IM_GEN_CRX_RG( crx, rg ), 0, 0, 0 )
#define X86IM_GEN_MOV_RG_CRX( io, mode, rg, crx )           x86im_gen( io, mode, X86IM_GEN_CODE_MOV_RG_CRX, X86IM_GEN_RG_CRX( rg, crx ), 0, 0, 0 )

#define X86IM_GEN_MOV_DRX_RG( io, mode, drx, rg )           x86im_gen( io, mode, X86IM_GEN_CODE_MOV_DRX_RG, X86IM_GEN_DRX_RG( drx, rg ), 0, 0, 0 )
#define X86IM_GEN_MOV_RG_DRX( io, mode, rg, drx )           x86im_gen( io, mode, X86IM_GEN_CODE_MOV_RG_DRX, X86IM_GEN_RG_DRX( rg, drx ), 0, 0, 0 )

#define X86IM_GEN_MOV_SRX_MM( io, mode, srx, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_MOV_SRX_MM, X86IM_GEN_SRX_MM( srx ), mm, 0 )
#define X86IM_GEN_MOV_MM_SRX( io, mode, mm, srx )           x86im_gen( io, mode, X86IM_GEN_CODE_MOV_MM_SRX, X86IM_GEN_MM_SRX( srx ), mm, 0 )
#define X86IM_GEN_MOV_SRX_RG( io, mode, srx, rg )           x86im_gen( io, mode, X86IM_GEN_CODE_MOV_SRX_RG, X86IM_GEN_SRX_RG( srx, rg ), 0, 0, 0 )

#define X86IM_GEN_MOV_RG_SRX_WORD( io, mode, rg, srx )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOV_RG_SRX, X86IM_GEN_RG_SRX( rg, srx ), 0, 0, 0 )
#define X86IM_GEN_MOV_RG_SRX_DWORD( io, mode, rg, srx )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOV_RG_SRX, X86IM_GEN_RG_SRX( rg, srx ), 0, 0, 0 )
#define X86IM_GEN_MOV_RG_SRX_QWORD( io, rg, srx )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOV_RG_SRX, X86IM_GEN_RG_SRX( rg, srx ), 0, 0, 0 )

#define X86IM_GEN_CODE_MOVSX_R1_R28                         0x00C0BE0F
#define X86IM_GEN_CODE_MOVSX_RG_MM8                         0x0000BE0F
#define X86IM_GEN_CODE_MOVSX_R1_R216                        0x00C0BF0F
#define X86IM_GEN_CODE_MOVSX_RG_MM16                        0x0000BF0F

#define X86IM_GEN_MOVSX_R1_R2_B2W( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVSX_R1_R28, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSX_R1_R2_B2D( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVSX_R1_R28, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSX_R1_R2_B2Q( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVSX_R1_R28, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_MOVSX_R1_R2_W2W( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVSX_R1_R216, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSX_R1_R2_W2D( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVSX_R1_R216, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSX_R1_R2_W2Q( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVSX_R1_R216, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_MOVSX_RG_MM_B2W( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVSX_RG_MM8, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVSX_RG_MM_B2D( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVSX_RG_MM8, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVSX_RG_MM_B2Q( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVSX_RG_MM8, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_MOVSX_RG_MM_W2W( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVSX_RG_MM16, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVSX_RG_MM_W2D( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVSX_RG_MM16, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVSX_RG_MM_W2Q( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVSX_RG_MM16, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_MOVZX_R1_R28                         0x00C0B60F
#define X86IM_GEN_CODE_MOVZX_RG_MM8                         0x0000B60F
#define X86IM_GEN_CODE_MOVZX_R1_R216                        0x00C0B70F
#define X86IM_GEN_CODE_MOVZX_RG_MM16                        0x0000B70F

#define X86IM_GEN_MOVZX_R1_R2_B2W( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVZX_R1_R28, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVZX_R1_R2_B2D( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVZX_R1_R28, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVZX_R1_R2_B2Q( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVZX_R1_R28, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_MOVZX_R1_R2_W2W( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVZX_R1_R216, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVZX_R1_R2_W2D( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVZX_R1_R216, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVZX_R1_R2_W2Q( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVZX_R1_R216, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_MOVZX_RG_MM_B2W( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVZX_RG_MM8, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVZX_RG_MM_B2D( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVZX_RG_MM8, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVZX_RG_MM_B2Q( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVZX_RG_MM8, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_MOVZX_RG_MM_W2W( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MOVZX_RG_MM16, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVZX_RG_MM_W2D( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MOVZX_RG_MM16, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_MOVZX_RG_MM_W2Q( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MOVZX_RG_MM16, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_MUL_AC_MM                            0x000020F6
#define X86IM_GEN_CODE_MUL_AC_RG                            0x0000E0F6

#define X86IM_GEN_MUL_AC_MM_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MUL_AC_MM, 0, mm, 0 )
#define X86IM_GEN_MUL_AC_MM_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MUL_AC_MM, 0, mm, 0 )
#define X86IM_GEN_MUL_AC_MM_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MUL_AC_MM, 0, mm, 0 )
#define X86IM_GEN_MUL_AC_MM_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MUL_AC_MM, 0, mm, 0 )

#define X86IM_GEN_MUL_AC_RG_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_MUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_MUL_AC_RG_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_MUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_MUL_AC_RG_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_MUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_MUL_AC_RG_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_MUL_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_NEG_MM                               0x000018F6
#define X86IM_GEN_CODE_NEG_RG                               0x0000D8F6

#define X86IM_GEN_NEG_MM_BYTE( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_NEG_MM, 0, mm, 0 )
#define X86IM_GEN_NEG_MM_WORD( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_NEG_MM, 0, mm, 0 )
#define X86IM_GEN_NEG_MM_DWORD( io, mode, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_NEG_MM, 0, mm, 0 )
#define X86IM_GEN_NEG_MM_QWORD( io, mm )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_NEG_MM, 0, mm, 0 )

#define X86IM_GEN_NEG_RG_BYTE( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_NEG_RG, rg, 0, 0, 0 )
#define X86IM_GEN_NEG_RG_WORD( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_NEG_RG, rg, 0, 0, 0 )
#define X86IM_GEN_NEG_RG_DWORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_NEG_RG, rg, 0, 0, 0 )
#define X86IM_GEN_NEG_RG_QWORD( io, rg )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_NEG_RG, X86IM_GEN_RG_MM( rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_NOT_MM                               0x000010F6
#define X86IM_GEN_CODE_NOT_RG                               0x0000D0F6

#define X86IM_GEN_NOT_MM_BYTE( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_NOT_MM, 0, mm, 0 )
#define X86IM_GEN_NOT_MM_WORD( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_NOT_MM, 0, mm, 0 )
#define X86IM_GEN_NOT_MM_DWORD( io, mode, mm  )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_NOT_MM, 0, mm, 0 )
#define X86IM_GEN_NOT_MM_QWORD( io, mm )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_NOT_MM, 0, mm, 0 )

#define X86IM_GEN_NOT_RG_BYTE( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_NOT_RG, rg, 0, 0, 0 )
#define X86IM_GEN_NOT_RG_WORD( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_NOT_RG, rg, 0, 0, 0 )
#define X86IM_GEN_NOT_RG_DWORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_NOT_RG, rg, 0, 0, 0 )
#define X86IM_GEN_NOT_RG_QWORD( io, rg )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_NOT_RG, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_OR_MM_RG                             0x00000008
#define X86IM_GEN_CODE_OR_R2_R1                             0x0000C008
#define X86IM_GEN_CODE_OR_RG_MM                             0x0000000A
#define X86IM_GEN_CODE_OR_R1_R2                             0x0000C00A
#define X86IM_GEN_CODE_OR_MM_IM                             0x00000880
#define X86IM_GEN_CODE_OR_RG_IM                             0x0000C880
#define X86IM_GEN_CODE_OR_AC_IM                             0x0000000C

#define X86IM_GEN_OR_MM_RG_BYTE( io, mode, mm, rg )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_OR_MM_RG_WORD( io, mode, mm, rg )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_OR_MM_RG_DWORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_OR_MM_RG_QWORD( io, mm, rg )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_OR_R2_R1_BYTE( io, mode, r2, r1 )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_OR_R2_R1_WORD( io, mode, r2, r1 )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_OR_R2_R1_DWORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_OR_R2_R1_QWORD( io, r2, r1 )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_OR_RG_MM_BYTE( io, mode, rg, mm )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_OR_RG_MM_WORD( io, mode, rg, mm )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_OR_RG_MM_DWORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_OR_RG_MM_QWORD( io, rg, mm )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_OR_R1_R2_BYTE( io, mode, r1, r2 )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_OR_R1_R2_WORD( io, mode, r1, r2 )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_OR_R1_R2_DWORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_OR_R1_R2_QWORD( io, r1, r2 )              x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_OR_MM_IM_BYTE( io, mode, mm, imm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm ) 
#define X86IM_GEN_OR_MM_IM_WORD( io, mode, mm, imm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm )
#define X86IM_GEN_OR_MM_IM_DWORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm )
#define X86IM_GEN_OR_MM_IM_QWORD( io, mm, imm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm )

#define X86IM_GEN_OR_MM_IM_SBYTE( io, mm, imm8 )            x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_OR_MM_IM_SWORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_OR_MM_IM_SDWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_OR_MM_IM_SQWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_OR_RG_IM_BYTE( io, mode, rg, imm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_OR_RG_IM_WORD( io, mode, rg, imm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_OR_RG_IM_DWORD( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_OR_RG_IM_QWORD( io, rg, imm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )

#define X86IM_GEN_OR_RG_IM_SBYTE( io, rg8, imm8 )            x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_OR_RG_IM_SWORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  
#define X86IM_GEN_OR_RG_IM_SDWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_OR_RG_IM_SQWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_OR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  

#define X86IM_GEN_OR_AC_IM_BYTE( io, mode, imm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_AC_IM, 0, 0, 0, imm )     
#define X86IM_GEN_OR_AC_IM_WORD( io, mode, imm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OR_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_OR_AC_IM_DWORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OR_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_OR_AC_IM_QWORD( io, imm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OR_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_OUT_IM                               0x000000E6
#define X86IM_GEN_CODE_OUT_RG                               0x000000EE

#define X86IM_GEN_OUT_IM_BYTE( io, mode, imm8 )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OUT_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_OUT_IM_WORD( io, mode, imm8 )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OUT_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_OUT_IM_DWORD( io, mode, imm8 )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OUT_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_OUT_IM_QWORD( io, imm8 )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OUT_IM, 0, 0, 0, imm8 )

#define X86IM_GEN_OUT_RG_BYTE( io, mode )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_OUT_RG, 0, 0, 0, 0 )
#define X86IM_GEN_OUT_RG_WORD( io, mode )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_OUT_RG, 0, 0, 0, 0 )
#define X86IM_GEN_OUT_RG_DWORD( io, mode )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_OUT_RG, 0, 0, 0, 0 )
#define X86IM_GEN_OUT_RG_QWORD( io )                        x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_OUT_RG, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_POP_MM                               0x0000008F
#define X86IM_GEN_CODE_POP_RG1                              0x0000C08F
#define X86IM_GEN_CODE_POP_RG2                              0x00000058
#define X86IM_GEN_CODE_POP_SR1                              0x00000007
#define X86IM_GEN_CODE_POP_SR2                              0x0000A10F
#define X86IM_GEN_CODE_POPAD                                0x00000061
#define X86IM_GEN_CODE_POPF                                 0x0000009D

#define X86IM_GEN_POP_MM_WORD( io, mode, mm )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_POP_MM, 0, mm, 0 )
#define X86IM_GEN_POP_MM_DWORD( io, mm )                    x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_POP_MM, 0, mm, 0 )
#define X86IM_GEN_POP_MM_QWORD( io, mm )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_POP_MM, 0, mm, 0 )

#define X86IM_GEN_POP_RG1_WORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_POP_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_POP_RG1_DWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_POP_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_POP_RG1_QWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_POP_RG1, rg, 0, 0, 0 )

#define X86IM_GEN_POP_RG2_WORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_POP_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_POP_RG2_DWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_POP_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_POP_RG2_QWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_POP_RG2, X86IM_GEN_OP_RG( rg ), 0 ,0 , 0 )

#define X86IM_GEN_POP_ES( io )                              x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_POP_SR1|X86IM_GEN_SREG2( X86IM_IO_ROP_ID_ES ), X86IM_GEN_SREG2( X86IM_IO_ROP_ID_ES ), 0, 0, 0 )
#define X86IM_GEN_POP_SS( io )                              x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_POP_SR1|X86IM_GEN_SREG2( X86IM_IO_ROP_ID_SS ), X86IM_GEN_SREG2( X86IM_IO_ROP_ID_SS ), 0, 0, 0 )
#define X86IM_GEN_POP_DS( io )                              x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_POP_SR1|X86IM_GEN_SREG2( X86IM_IO_ROP_ID_DS ), X86IM_GEN_SREG2( X86IM_IO_ROP_ID_DS ), 0, 0, 0 )

#define X86IM_GEN_POP_FS( io, mode )                        x86im_gen( io, mode, X86IM_GEN_CODE_POP_SR2|X86IM_GEN_SREG3( X86IM_IO_ROP_ID_FS ), 0, 0, 0, 0 )
#define X86IM_GEN_POP_GS( io, mode )                        x86im_gen( io, mode, X86IM_GEN_CODE_POP_SR2|X86IM_GEN_SREG3( X86IM_IO_ROP_ID_GS ), 0, 0, 0, 0 )

#define X86IM_GEN_POPAD( io )                               x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_POPAD, 0, 0, 0, 0 ) 
#define X86IM_GEN_POPF( io )                                x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_POPF, 0, 0, 0, 0 )
#define X86IM_GEN_POPFD( io )                               x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_POPF, 0, 0, 0, 0 )
#define X86IM_GEN_POPFQ( io )                               x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_POPF, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_PUSH_MM                              0x000030FF
#define X86IM_GEN_CODE_PUSH_RG1                             0x0000F0FF
#define X86IM_GEN_CODE_PUSH_RG2                             0x00000050
#define X86IM_GEN_CODE_PUSH_IM                              0x00000068
#define X86IM_GEN_CODE_PUSH_SR1                             0x00000006
#define X86IM_GEN_CODE_PUSH_SR2                             0x0000A00F
#define X86IM_GEN_CODE_PUSHAD                               0x00000060
#define X86IM_GEN_CODE_PUSHF                                0x0000009C

#define X86IM_GEN_PUSH_MM_WORD( io, mode, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_PUSH_MM, 0, mm, 0 )
#define X86IM_GEN_PUSH_MM_DWORD( io, mm )                   x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_PUSH_MM, 0, mm, 0 )
#define X86IM_GEN_PUSH_MM_QWORD( io, mm )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_PUSH_MM, 0, mm, 0 )

#define X86IM_GEN_PUSH_RG1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_PUSH_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_PUSH_RG1_DWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_PUSH_RG1, rg, 0, 0, 0 )
#define X86IM_GEN_PUSH_RG1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_PUSH_RG1, rg, 0, 0, 0 )

#define X86IM_GEN_PUSH_RG2_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_PUSH_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_PUSH_RG2_DWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_PUSH_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_PUSH_RG2_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_PUSH_RG2, X86IM_GEN_OP_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_PUSH_IM_BYTE( io, mode, imm8 )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_PUSH_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_PUSH_IM_WORD( io, mode, imm16 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_PUSH_IM, 0, 0, 0, imm16 )
#define X86IM_GEN_PUSH_IM_DWORD( io, mode, imm32 )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_PUSH_IM, 0, 0, 0, imm32 )

#define X86IM_GEN_PUSH_IM_SBYTE( io, mode, imm8 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_PUSH_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_PUSH_IM_SWORD( io, mode, imm8 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_PUSH_IM, 0, 0, 0, imm8 )
#define X86IM_GEN_PUSH_IM_SDWORD( io, mode, imm8 )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_PUSH_IM, 0, 0, 0, imm8 )

#define X86IM_GEN_PUSH_ES( io )                             x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_PUSH_SR1|X86IM_GEN_SREG2( X86IM_IO_ROP_ID_ES ), 0, 0, 0, 0 )
#define X86IM_GEN_PUSH_CS( io )                             x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_PUSH_SR1|X86IM_GEN_SREG2( X86IM_IO_ROP_ID_CS ), 0, 0, 0, 0 )
#define X86IM_GEN_PUSH_DS( io )                             x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_PUSH_SR1|X86IM_GEN_SREG2( X86IM_IO_ROP_ID_DS ), 0, 0, 0, 0 )
#define X86IM_GEN_PUSH_SS( io )                             x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_PUSH_SR1|X86IM_GEN_SREG2( X86IM_IO_ROP_ID_SS ), 0, 0, 0, 0 )

#define X86IM_GEN_PUSH_FS( io, mode )                       x86im_gen( io, mode, X86IM_GEN_CODE_PUSH_SR2|X86IM_GEN_SREG3( X86IM_IO_ROP_ID_FS ), 0, 0, 0, 0 )
#define X86IM_GEN_PUSH_GS( io, mode )                       x86im_gen( io, mode, X86IM_GEN_CODE_PUSH_SR2|X86IM_GEN_SREG3( X86IM_IO_ROP_ID_GS ), 0, 0, 0, 0 )

#define X86IM_GEN_PUSHAD( io )                              x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_PUSHAD, 0, 0, 0, 0 )

#define X86IM_GEN_PUSHF( io, mode )                         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_PUSHF, 0, 0, 0, 0 )  
#define X86IM_GEN_PUSHFD( io )                              x86im_gen( io, X86IM_IO_MODE_32BIT, X86IM_GEN_CODE_PUSHF, 0, 0, 0, 0 )     
#define X86IM_GEN_PUSHFQ( io )                              x86im_gen( io, X86IM_IO_MODE_64BIT, X86IM_GEN_CODE_PUSHF, 0, 0, 0, 0 ) 

#define X86IM_GEN_CODE_RCL_MM_1                             0x000010D0
#define X86IM_GEN_CODE_RCL_RG_1                             0x0000D0D0
#define X86IM_GEN_CODE_RCL_MM_CL                            0x000010D2
#define X86IM_GEN_CODE_RCL_RG_CL                            0x0000D0D2
#define X86IM_GEN_CODE_RCL_MM_IM                            0x000010C0
#define X86IM_GEN_CODE_RCL_RG_IM                            0x0000D0C0

#define X86IM_GEN_RCL_MM_1_BYTE( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCL_MM_1, 0, mm, 0 )
#define X86IM_GEN_RCL_MM_1_WORD( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCL_MM_1, 0, mm,0 )
#define X86IM_GEN_RCL_MM_1_DWORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCL_MM_1, 0, mm, 0 )
#define X86IM_GEN_RCL_MM_1_QWORD( io, mm )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCL_MM_1, 0, mm, 0 )

#define X86IM_GEN_RCL_RG_1_BYTE( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_RCL_RG_1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_RCL_RG_1_DWORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_RCL_RG_1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )

#define X86IM_GEN_RCL_MM_CL_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_RCL_MM_CL_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_RCL_MM_CL_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_RCL_MM_CL_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCL_MM_CL, 0, mm, 0 )

#define X86IM_GEN_RCL_RG_CL_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_RCL_RG_CL_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_RCL_RG_CL_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_RCL_RG_CL_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCL_RG_CL, rg, 0, 0, 0 )

#define X86IM_GEN_RCL_MM_IM_BYTE( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_RCL_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_RCL_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_RCL_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCL_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_RCL_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )    
#define X86IM_GEN_RCL_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_RCL_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_RCL_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_RCR_MM_1                             0x000018D0
#define X86IM_GEN_CODE_RCR_RG_1                             0x0000D8D0
#define X86IM_GEN_CODE_RCR_MM_CL                            0x000018D2
#define X86IM_GEN_CODE_RCR_RG_CL                            0x0000D8D2
#define X86IM_GEN_CODE_RCR_MM_IM                            0x000018C0
#define X86IM_GEN_CODE_RCR_RG_IM                            0x0000D8C0

#define X86IM_GEN_RCR_MM_1_BYTE( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCR_MM_1, 0, mm, 0 )
#define X86IM_GEN_RCR_MM_1_WORD( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCR_MM_1, 0, mm, 0 )
#define X86IM_GEN_RCR_MM_1_DWORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCR_MM_1, 0, mm, 0 )
#define X86IM_GEN_RCR_MM_1_QWORD( io, mm )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCR_MM_1, 0, mm, 0 )

#define X86IM_GEN_RCR_RG_1_BYTE( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_RCR_RG_1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_RCR_RG_1_DWORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_RCR_RG_1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )

#define X86IM_GEN_RCR_MM_CL_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_RCR_MM_CL_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_RCR_MM_CL_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_RCR_MM_CL_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCR_MM_CL, 0, mm, 0 )

#define X86IM_GEN_RCR_RG_CL_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_RCR_RG_CL_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_RCR_RG_CL_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCR_RG_CL, rg, 0, 0, 0  )
#define X86IM_GEN_RCR_RG_CL_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCR_RG_CL, rg, 0, 0, 0 )

#define X86IM_GEN_RCR_MM_IM_BYTE( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_RCR_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_RCR_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_RCR_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCR_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_RCR_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_RCR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )    
#define X86IM_GEN_RCR_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_RCR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_RCR_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_RCR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_RCR_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_RCR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_RET_N                                0x000000C3
#define X86IM_GEN_CODE_RET_N_IM                             0x000000C2
#define X86IM_GEN_CODE_RET_F                                0x000000CB
#define X86IM_GEN_CODE_RET_F_IM                             0x000000CA

#define X86IM_GEN_RET_N( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_RET_N, 0, 0, 0, 0 )
#define X86IM_GEN_RET_N_IM( io, mode, imm16 )               x86im_gen( io, mode, X86IM_GEN_CODE_RET_N_IM, 0, 0, 0, imm16 )
#define X86IM_GEN_RET_F( io, mode )                         x86im_gen( io, mode, X86IM_GEN_CODE_RET_F, 0, 0, 0, 0 )
#define X86IM_GEN_RET_F_IM( io, mode, imm16 )               x86im_gen( io, mode, X86IM_GEN_CODE_RET_F_IM, 0, 0, 0, imm16 )

#define X86IM_GEN_CODE_ROL_MM_1                             0x000000D0
#define X86IM_GEN_CODE_ROL_RG_1                             0x0000C0D0
#define X86IM_GEN_CODE_ROL_MM_CL                            0x000000D2
#define X86IM_GEN_CODE_ROL_RG_CL                            0x0000C0D2
#define X86IM_GEN_CODE_ROL_MM_IM                            0x000000C0
#define X86IM_GEN_CODE_ROL_RG_IM                            0x0000C0C0

#define X86IM_GEN_ROL_MM_1_BYTE( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROL_MM_1, 0, mm, 0 )
#define X86IM_GEN_ROL_MM_1_WORD( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROL_MM_1, 0, mm, 0 )
#define X86IM_GEN_ROL_MM_1_DWORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROL_MM_1, 0, mm, 0 )
#define X86IM_GEN_ROL_MM_1_QWORD( io, mm )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROL_MM_1, 0, mm, 0 )

#define X86IM_GEN_ROL_RG_1_BYTE( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_ROL_RG_1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_ROL_RG_1_DWORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_ROL_RG_1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )

#define X86IM_GEN_ROL_MM_CL_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_ROL_MM_CL_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_ROL_MM_CL_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_ROL_MM_CL_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROL_MM_CL, 0, mm, 0 )

#define X86IM_GEN_ROL_RG_CL_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_ROL_RG_CL_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_ROL_RG_CL_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_ROL_RG_CL_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROL_RG_CL, rg, 0, 0, 0 )

#define X86IM_GEN_ROL_MM_IM_BYTE( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ROL_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ROL_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ROL_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROL_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_ROL_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )    
#define X86IM_GEN_ROL_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ROL_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ROL_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_ROR_MM_1                             0x000008D0
#define X86IM_GEN_CODE_ROR_RG_1                             0x0000C8D0
#define X86IM_GEN_CODE_ROR_MM_CL                            0x000008D2
#define X86IM_GEN_CODE_ROR_RG_CL                            0x0000C8D2
#define X86IM_GEN_CODE_ROR_MM_IM                            0x000008C0
#define X86IM_GEN_CODE_ROR_RG_IM                            0x0000C8C0

#define X86IM_GEN_ROR_MM_1_BYTE( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROR_MM_1, 0, mm, 0 )
#define X86IM_GEN_ROR_MM_1_WORD( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROR_MM_1, 0, mm, 0 )
#define X86IM_GEN_ROR_MM_1_DWORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROR_MM_1, 0, mm, 0 )
#define X86IM_GEN_ROR_MM_1_QWORD( io, mm )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROR_MM_1, 0, mm, 0 )

#define X86IM_GEN_ROR_RG_1_BYTE( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_ROR_RG_1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_ROR_RG_1_DWORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_ROR_RG_1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )

#define X86IM_GEN_ROR_MM_CL_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_ROR_MM_CL_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_ROR_MM_CL_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_ROR_MM_CL_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROR_MM_CL, 0, mm, 0 )

#define X86IM_GEN_ROR_RG_CL_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_ROR_RG_CL_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_ROR_RG_CL_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_ROR_RG_CL_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROR_RG_CL, rg, 0, 0, 0 )

#define X86IM_GEN_ROR_MM_IM_BYTE( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ROR_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ROR_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_ROR_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROR_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_ROR_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_ROR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )    
#define X86IM_GEN_ROR_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_ROR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ROR_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_ROR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_ROR_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_ROR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_SAR_MM_1                             0x000038D0
#define X86IM_GEN_CODE_SAR_RG_1                             0x0000F8D0
#define X86IM_GEN_CODE_SAR_MM_CL                            0x000038D2
#define X86IM_GEN_CODE_SAR_RG_CL                            0x0000F8D2
#define X86IM_GEN_CODE_SAR_MM_IM                            0x000038C0
#define X86IM_GEN_CODE_SAR_RG_IM                            0x0000F8C0

#define X86IM_GEN_SAR_MM_1_BYTE( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SAR_MM_1, 0, mm, 0 )
#define X86IM_GEN_SAR_MM_1_WORD( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SAR_MM_1, 0, mm, 0 )
#define X86IM_GEN_SAR_MM_1_DWORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SAR_MM_1, 0, mm, 0 )
#define X86IM_GEN_SAR_MM_1_QWORD( io, mm )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SAR_MM_1, 0, mm, 0 )

#define X86IM_GEN_SAR_RG_1_BYTE( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SAR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SAR_RG_1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SAR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SAR_RG_1_DWORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SAR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SAR_RG_1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SAR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )

#define X86IM_GEN_SAR_MM_CL_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SAR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SAR_MM_CL_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SAR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SAR_MM_CL_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SAR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SAR_MM_CL_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SAR_MM_CL, 0, mm, 0 )

#define X86IM_GEN_SAR_RG_CL_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SAR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SAR_RG_CL_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SAR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SAR_RG_CL_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SAR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SAR_RG_CL_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SAR_RG_CL, rg, 0, 0, 0 )

#define X86IM_GEN_SAR_MM_IM_BYTE( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SAR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SAR_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SAR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SAR_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SAR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SAR_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SAR_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_SAR_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SAR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )    
#define X86IM_GEN_SAR_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SAR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SAR_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SAR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SAR_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SAR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_SBB_MM_RG                            0x00000018
#define X86IM_GEN_CODE_SBB_R2_R1                            0x0000C018
#define X86IM_GEN_CODE_SBB_RG_MM                            0x0000001A
#define X86IM_GEN_CODE_SBB_R1_R2                            0x0000C01A
#define X86IM_GEN_CODE_SBB_MM_IM                            0x00001880
#define X86IM_GEN_CODE_SBB_RG_IM                            0x0000D880
#define X86IM_GEN_CODE_SBB_AC_IM                            0x0000001C

#define X86IM_GEN_SBB_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SBB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SBB_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SBB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SBB_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SBB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SBB_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SBB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_SBB_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SBB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_SBB_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SBB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_SBB_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SBB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_SBB_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SBB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_SBB_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SBB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_SBB_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SBB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_SBB_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SBB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_SBB_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SBB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_SBB_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SBB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SBB_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SBB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SBB_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SBB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SBB_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SBB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_SBB_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm ) 
#define X86IM_GEN_SBB_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm )
#define X86IM_GEN_SBB_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm )
#define X86IM_GEN_SBB_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm )

#define X86IM_GEN_SBB_MM_IM_SBYTE( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SBB_MM_IM_SWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SBB_MM_IM_SDWORD( io, mode, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SBB_MM_IM_SQWORD( io, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_SBB_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SBB_RG_IM_WORD( io, mode, rg, imm16 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm16 )
#define X86IM_GEN_SBB_RG_IM_DWORD( io, mode, rg, imm32 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )
#define X86IM_GEN_SBB_RG_IM_QWORD( io, rg, imm32 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )

#define X86IM_GEN_SBB_RG_IM_SBYTE( io, rg8, imm8 )          x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_SBB_RG_IM_SWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  
#define X86IM_GEN_SBB_RG_IM_SDWORD( io, mode, rg, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SBB_RG_IM_SQWORD( io, rg, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SBB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  

#define X86IM_GEN_SBB_AC_IM_BYTE( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SBB_AC_IM, 0, 0, 0, imm )     
#define X86IM_GEN_SBB_AC_IM_WORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SBB_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_SBB_AC_IM_DWORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SBB_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_SBB_AC_IM_QWORD( io, imm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SBB_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_SETCC_MM                             0x0000900F
#define X86IM_GEN_CODE_SETCC_RG                             0x00C0900F

#define X86IM_GEN_SETO_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_O ), mm, 0 )
#define X86IM_GEN_SETNO_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NO ), mm, 0 )
#define X86IM_GEN_SETB_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_B ), mm, 0 )
#define X86IM_GEN_SETC_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_C ), mm, 0 )
#define X86IM_GEN_SETNAE_MM( io, mode, mm )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NAE ), mm, 0 )
#define X86IM_GEN_SETAE_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_AE ), mm, 0 )
#define X86IM_GEN_SETNB_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NB ), mm, 0 )
#define X86IM_GEN_SETNC_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NC ), mm, 0 )
#define X86IM_GEN_SETE_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_E ), mm, 0 )
#define X86IM_GEN_SETZ_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_Z ), mm, 0 )
#define X86IM_GEN_SETNE_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NE ), mm, 0 )
#define X86IM_GEN_SETNZ_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NZ ), mm, 0 )
#define X86IM_GEN_SETBE_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_BE ), mm, 0 )
#define X86IM_GEN_SETNA_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NA ), mm, 0 )
#define X86IM_GEN_SETA_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_A ), mm, 0 )
#define X86IM_GEN_SETNBE_MM( io, mode, mm )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NBE ), mm, 0 )
#define X86IM_GEN_SETS_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_S ), mm, 0 )
#define X86IM_GEN_SETNS_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NS ), mm, 0 )
#define X86IM_GEN_SETP_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_P ), mm, 0 )
#define X86IM_GEN_SETPE_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_PE ), mm, 0 )
#define X86IM_GEN_SETNP_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NP ), mm, 0 )
#define X86IM_GEN_SETPO_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_PO ), mm, 0 )
#define X86IM_GEN_SETL_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_L ), mm, 0 )
#define X86IM_GEN_SETNGE_MM( io, mode, mm )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NGE ), mm, 0 )
#define X86IM_GEN_SETNL_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NL ), mm, 0 )
#define X86IM_GEN_SETGE_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_GE ), mm, 0 )
#define X86IM_GEN_SETLE_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_LE ), mm, 0 )
#define X86IM_GEN_SETNG_MM( io, mode, mm )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NG ), mm, 0 )
#define X86IM_GEN_SETNLE_MM( io, mode, mm )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_NLE ), mm, 0 )
#define X86IM_GEN_SETG_MM( io, mode, mm )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_MM, X86IM_GEN_TTTN( X86IM_IO_TN_G ), mm, 0 )

#define X86IM_GEN_SETO_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_O, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNO_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NO, rg ), 0, 0, 0 )
#define X86IM_GEN_SETB_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_B, rg ), 0, 0, 0 )
#define X86IM_GEN_SETC_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_C, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNAE_RG( io, mode, rg )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NAE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETAE_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_AE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNB_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NB, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNC_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NC, rg ), 0, 0, 0 )
#define X86IM_GEN_SETE_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_E, rg ), 0, 0, 0 )
#define X86IM_GEN_SETZ_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_Z, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNE_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNZ_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NZ, rg ), 0, 0, 0 )
#define X86IM_GEN_SETBE_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_BE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNA_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NA, rg ), 0, 0, 0 )
#define X86IM_GEN_SETA_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_A, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNBE_RG( io, mode, rg )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NBE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETS_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_S, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNS_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NS, rg ), 0, 0, 0 )
#define X86IM_GEN_SETP_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_P, rg ), 0, 0, 0 )
#define X86IM_GEN_SETPE_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_PE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNP_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NP, rg ), 0, 0, 0 )
#define X86IM_GEN_SETPO_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_PO, rg ), 0, 0, 0 )
#define X86IM_GEN_SETL_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_L, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNGE_RG( io, mode, rg )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NGE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNL_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NL, rg ), 0, 0, 0 )
#define X86IM_GEN_SETGE_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_GE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETLE_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_LE,rg ), 0, 0, 0 )
#define X86IM_GEN_SETNG_RG( io, mode, rg )                  x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NG, rg ), 0, 0, 0 )
#define X86IM_GEN_SETNLE_RG( io, mode, rg )                 x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_NLE, rg ), 0, 0, 0 )
#define X86IM_GEN_SETG_RG( io, mode, rg )                   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SETCC_RG, X86IM_GEN_TTTN_RG( X86IM_IO_TN_G, rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_SHL_MM_1                             0x000020D0
#define X86IM_GEN_CODE_SHL_RG_1                             0x0000E0D0
#define X86IM_GEN_CODE_SHL_MM_CL                            0x000020D2
#define X86IM_GEN_CODE_SHL_RG_CL                            0x0000E0D2
#define X86IM_GEN_CODE_SHL_MM_IM                            0x000020C0
#define X86IM_GEN_CODE_SHL_RG_IM                            0x0000E0C0
    
#define X86IM_GEN_SHL_MM_1_BYTE( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHL_MM_1, 0, mm, 0 )
#define X86IM_GEN_SHL_MM_1_WORD( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHL_MM_1, 0, mm, 0 )
#define X86IM_GEN_SHL_MM_1_DWORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHL_MM_1, 0, mm, 0 )
#define X86IM_GEN_SHL_MM_1_QWORD( io, mm )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHL_MM_1, 0, mm, 0 )

#define X86IM_GEN_SHL_RG_1_BYTE( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SHL_RG_1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SHL_RG_1_DWORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SHL_RG_1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHL_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
    
#define X86IM_GEN_SHL_MM_CL_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SHL_MM_CL_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SHL_MM_CL_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHL_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SHL_MM_CL_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHL_MM_CL, 0, mm, 0 )

#define X86IM_GEN_SHL_RG_CL_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SHL_RG_CL_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SHL_RG_CL_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHL_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SHL_RG_CL_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHL_RG_CL, rg, 0, 0, 0 )

#define X86IM_GEN_SHL_MM_IM_BYTE( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SHL_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SHL_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHL_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SHL_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHL_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_SHL_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )    
#define X86IM_GEN_SHL_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SHL_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SHL_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHL_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_SHLD_MM_RG_IM                                0x0000A40F
#define X86IM_GEN_CODE_SHLD_R1_R2_IM                                0x00C0A40F
#define X86IM_GEN_CODE_SHLD_MM_RG_CL                                0x0000A50F
#define X86IM_GEN_CODE_SHLD_R1_R2_CL                                0x00C0A50F

#define X86IM_GEN_SHLD_MM_RG_IM_WORD( io, mode, mm, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHLD_MM_RG_IM, X86IM_GEN_MM_RG( rg ), mm, imm8 )
#define X86IM_GEN_SHLD_MM_RG_IM_DWORD( io, mode, mm, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHLD_MM_RG_IM, X86IM_GEN_MM_RG( rg ), mm, imm8 )
#define X86IM_GEN_SHLD_MM_RG_IM_QWORD( io, mm, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHLD_MM_RG_IM, X86IM_GEN_MM_RG( rg ), mm, imm8 )

#define X86IM_GEN_SHLD_R1_R2_IM_WORD( io, mode, r1, r2, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHLD_R1_R2_IM, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, imm8 )
#define X86IM_GEN_SHLD_R1_R2_IM_DWORD( io, mode, r1, r2, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHLD_R1_R2_IM, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, imm8 )
#define X86IM_GEN_SHLD_R1_R2_IM_QWORD( io, r1, r2, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHLD_R1_R2_IM, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, imm8 )

#define X86IM_GEN_SHLD_MM_RG_CL_WORD( io, mode, mm, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHLD_MM_RG_CL, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SHLD_MM_RG_CL_DWORD( io, mode, mm, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHLD_MM_RG_CL, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SHLD_MM_RG_CL_QWORD( io, mm, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHLD_MM_RG_CL, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_SHLD_R1_R2_CL_WORD( io, mode, r1, r2 )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHLD_R1_R2_CL, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SHLD_R1_R2_CL_DWORD( io, mode, r1, r2 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHLD_R1_R2_CL, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SHLD_R1_R2_CL_QWORD( io, r1, r2 )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHLD_R1_R2_CL, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_SHR_MM_1                             0x000028D0
#define X86IM_GEN_CODE_SHR_RG_1                             0x0000E8D0
#define X86IM_GEN_CODE_SHR_MM_CL                            0x000028D2
#define X86IM_GEN_CODE_SHR_RG_CL                            0x0000E8D2
#define X86IM_GEN_CODE_SHR_MM_IM                            0x000028C0
#define X86IM_GEN_CODE_SHR_RG_IM                            0x0000E8C0

#define X86IM_GEN_SHR_MM_1_BYTE( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHR_MM_1, 0, mm, 0 )
#define X86IM_GEN_SHR_MM_1_WORD( io, mode, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHR_MM_1, 0, mm, 0 )
#define X86IM_GEN_SHR_MM_1_DWORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHR_MM_1, 0, mm, 0 )
#define X86IM_GEN_SHR_MM_1_QWORD( io, mm )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHR_MM_1, 0, mm, 0 )

#define X86IM_GEN_SHR_RG_1_BYTE( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SHR_RG_1_WORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SHR_RG_1_DWORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
#define X86IM_GEN_SHR_RG_1_QWORD( io, rg )                  x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHR_RG_1, X86IM_GEN_RG_IM( rg ), 0, 0, 0 )
    
#define X86IM_GEN_SHR_MM_CL_BYTE( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SHR_MM_CL_WORD( io, mode, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SHR_MM_CL_DWORD( io, mode, mm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHR_MM_CL, 0, mm, 0 )
#define X86IM_GEN_SHR_MM_CL_QWORD( io, mm )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHR_MM_CL, 0, mm, 0 )

#define X86IM_GEN_SHR_RG_CL_BYTE( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SHR_RG_CL_WORD( io, mode, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SHR_RG_CL_DWORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHR_RG_CL, rg, 0, 0, 0 )
#define X86IM_GEN_SHR_RG_CL_QWORD( io, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHR_RG_CL, rg, 0, 0, 0 )

#define X86IM_GEN_SHR_MM_IM_BYTE( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SHR_MM_IM_WORD( io, mode, mm, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SHR_MM_IM_DWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SHR_MM_IM_QWORD( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHR_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_SHR_RG_IM_BYTE( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SHR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )    
#define X86IM_GEN_SHR_RG_IM_WORD( io, mode, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SHR_RG_IM_DWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SHR_RG_IM_QWORD( io, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )

#define X86IM_GEN_CODE_SHRD_MM_RG_IM                                0x0000AC0F
#define X86IM_GEN_CODE_SHRD_R1_R2_IM                                0x00C0AC0F
#define X86IM_GEN_CODE_SHRD_MM_RG_CL                                0x0000AD0F
#define X86IM_GEN_CODE_SHRD_R1_R2_CL                                0x00C0AD0F
       
#define X86IM_GEN_SHRD_MM_RG_IM_WORD( io, mode, mm, rg, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHRD_MM_RG_IM, X86IM_GEN_MM_RG( rg ), mm, imm8 )
#define X86IM_GEN_SHRD_MM_RG_IM_DWORD( io, mode, mm, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHRD_MM_RG_IM, X86IM_GEN_MM_RG( rg ), mm, imm8 )
#define X86IM_GEN_SHRD_MM_RG_IM_QWORD( io, mm, rg, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHRD_MM_RG_IM, X86IM_GEN_MM_RG( rg ), mm, imm8 )

#define X86IM_GEN_SHRD_R1_R2_IM_WORD( io, mode, r1, r2, imm8 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHRD_R1_R2_IM, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, imm8 )
#define X86IM_GEN_SHRD_R1_R2_IM_DWORD( io, mode, r1, r2, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHRD_R1_R2_IM, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, imm8 )
#define X86IM_GEN_SHRD_R1_R2_IM_QWORD( io, r1, r2, imm8 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHRD_R1_R2_IM, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, imm8 )

#define X86IM_GEN_SHRD_MM_RG_CL_WORD( io, mode, mm, rg )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHRD_MM_RG_CL, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SHRD_MM_RG_CL_DWORD( io, mode, mm, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHRD_MM_RG_CL, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SHRD_MM_RG_CL_QWORD( io, mm, rg )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHRD_MM_RG_CL, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_SHRD_R1_R2_CL_WORD( io, mode, r1, r2 )            x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SHRD_R1_R2_CL, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SHRD_R1_R2_CL_DWORD( io, mode, r1, r2 )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SHRD_R1_R2_CL, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SHRD_R1_R2_CL_QWORD( io, r1, r2 )                 x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SHRD_R1_R2_CL, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_SLDT_MM                              0x0000000F
#define X86IM_GEN_CODE_SLDT_RG                              0x00C0000F

#define X86IM_GEN_SLDT_MM( io, mode, mm )                   x86im_gen( io, mode, X86IM_GEN_CODE_SLDT_MM, 0, mm, 0 )
#define X86IM_GEN_SLDT_RG_WORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SLDT_RG, rg, 0, 0, 0 )
#define X86IM_GEN_SLDT_RG_DWORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SLDT_RG, rg, 0, 0, 0 )
#define X86IM_GEN_SLDT_RG_QWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SLDT_RG, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_SMSW_MM                              0x0020010F
#define X86IM_GEN_CODE_SMSW_RG                              0x00E0010F

#define X86IM_GEN_SMSW_MM( io, mode, mm )                   x86im_gen( io, mode, X86IM_GEN_CODE_SMSW_MM, 0, mm, 0 ) 
#define X86IM_GEN_SMSW_RG_WORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SMSW_RG, rg, 0, 0, 0 )
#define X86IM_GEN_SMSW_RG_DWORD( io, mode, rg )             x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SMSW_RG, rg, 0, 0, 0 )
#define X86IM_GEN_SMSW_RG_QWORD( io, rg )                   x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SMSW_RG, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_STR_MM                               0x0008000F
#define X86IM_GEN_CODE_STR_RG                               0x00C8000F

#define X86IM_GEN_STR_MM( io, mode, mm )                    x86im_gen( io, mode, X86IM_GEN_CODE_STR_MM, 0, mm, 0 )
#define X86IM_GEN_STR_RG_WORD( io, mode, rg )               x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_STR_RG, rg, 0, 0, 0 )
#define X86IM_GEN_STR_RG_DWORD( io, mode, rg )              x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_STR_RG, rg, 0, 0, 0 )
#define X86IM_GEN_STR_RG_QWORD( io, rg )                    x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_STR_RG, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_SUB_MM_RG                            0x00000028
#define X86IM_GEN_CODE_SUB_R2_R1                            0x0000C028
#define X86IM_GEN_CODE_SUB_RG_MM                            0x0000002A
#define X86IM_GEN_CODE_SUB_R1_R2                            0x0000C02A
#define X86IM_GEN_CODE_SUB_MM_IM                            0x00002880
#define X86IM_GEN_CODE_SUB_RG_IM                            0x0000E880
#define X86IM_GEN_CODE_SUB_AC_IM                            0x0000002C

#define X86IM_GEN_SUB_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SUB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_SUB_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SUB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_SUB_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SUB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_SUB_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SUB_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_SUB_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SUB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_SUB_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SUB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_SUB_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SUB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_SUB_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SUB_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_SUB_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SUB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SUB_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SUB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SUB_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SUB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_SUB_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SUB_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_SUB_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SUB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SUB_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SUB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SUB_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SUB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_SUB_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SUB_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_SUB_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm ) 
#define X86IM_GEN_SUB_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm )
#define X86IM_GEN_SUB_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm )
#define X86IM_GEN_SUB_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm )

#define X86IM_GEN_SUB_MM_IM_SBYTE( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SUB_MM_IM_SWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SUB_MM_IM_SDWORD( io, mode, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_SUB_MM_IM_SQWORD( io, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_SUB_RG_IM_BYTE( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_SUB_RG_IM_WORD( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_SUB_RG_IM_DWORD( io, mode, rg, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_SUB_RG_IM_QWORD( io, rg, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )

#define X86IM_GEN_SUB_RG_IM_SBYTE( io, rg8, imm8 )          x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_SUB_RG_IM_SWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  
#define X86IM_GEN_SUB_RG_IM_SDWORD( io, mode, rg, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_SUB_RG_IM_SQWORD( io, rg, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_SUB_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  

#define X86IM_GEN_SUB_AC_IM_BYTE( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_SUB_AC_IM, 0, 0, 0, imm )     
#define X86IM_GEN_SUB_AC_IM_WORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_SUB_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_SUB_AC_IM_DWORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_SUB_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_SUB_AC_IM_QWORD( io, imm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_SUB_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_TEST_MM_RG                           0x00000084
#define X86IM_GEN_CODE_TEST_R1_R2                           0x0000C084
#define X86IM_GEN_CODE_TEST_MM_IM                           0x000000F6
#define X86IM_GEN_CODE_TEST_RG_IM                           0x0000C0F6
#define X86IM_GEN_CODE_TEST_AC_IM                           0x000000A8

#define X86IM_GEN_TEST_MM_RG_BYTE( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_TEST_MM_RG, X86IM_GEN_MM_RG( rg ), mm , 0 )
#define X86IM_GEN_TEST_MM_RG_WORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_TEST_MM_RG, X86IM_GEN_MM_RG( rg ), mm , 0 )
#define X86IM_GEN_TEST_MM_RG_DWORD( io, mode, mm, rg )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_TEST_MM_RG, X86IM_GEN_MM_RG( rg ), mm , 0 )
#define X86IM_GEN_TEST_MM_RG_QWORD( io, mm, rg )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_TEST_MM_RG, X86IM_GEN_MM_RG( rg ), mm , 0 )

#define X86IM_GEN_TEST_R1_R2_BYTE( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_TEST_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_TEST_R1_R2_WORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_TEST_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_TEST_R1_R2_DWORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_TEST_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_TEST_R1_R2_QWORD( io, r1, r2 )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_TEST_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_TEST_MM_IM_BYTE( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_TEST_MM_IM, 0, mm, imm ) 
#define X86IM_GEN_TEST_MM_IM_WORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_TEST_MM_IM, 0, mm, imm )
#define X86IM_GEN_TEST_MM_IM_DWORD( io, mode, mm, imm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_TEST_MM_IM, 0, mm, imm )
#define X86IM_GEN_TEST_MM_IM_QWORD( io, mm, imm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_TEST_MM_IM, 0, mm, imm )

#define X86IM_GEN_TEST_RG_IM_BYTE( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_TEST_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_TEST_RG_IM_WORD( io, mode, rg, imm16 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_TEST_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm16 )
#define X86IM_GEN_TEST_RG_IM_DWORD( io, mode, rg, imm32 )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_TEST_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )
#define X86IM_GEN_TEST_RG_IM_QWORD( io, rg, imm32 )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_TEST_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm32 )

#define X86IM_GEN_TEST_AC_IM_BYTE( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_TEST_AC_IM, 0, 0, 0, imm )     
#define X86IM_GEN_TEST_AC_IM_WORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_TEST_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_TEST_AC_IM_DWORD( io, mode, imm )         x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_TEST_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_TEST_AC_IM_QWORD( io, imm )               x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_TEST_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_VERR_MM                              0x0020000F
#define X86IM_GEN_CODE_VERR_RG                              0x00E0000F

#define X86IM_GEN_VERR_MM( io, mode, mm )                   x86im_gen( io, mode, X86IM_GEN_CODE_VERR_MM, 0, mm, 0 )
#define X86IM_GEN_VERR_RG( io, mode, rg )                   x86im_gen( io, mode, X86IM_GEN_CODE_VERR_RG, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_VERW_MM                              0x0028000F
#define X86IM_GEN_CODE_VERW_RG                              0x00E8000F

#define X86IM_GEN_VERW_MM( io, mode, mm )                   x86im_gen( io, mode, X86IM_GEN_CODE_VERW_MM, 0, mm, 0 )
#define X86IM_GEN_VERW_RG( io, mode, rg )                   x86im_gen( io, mode, X86IM_GEN_CODE_VERW_RG, rg, 0, 0, 0 )

#define X86IM_GEN_CODE_XADD_MM_RG                           0x0000C00F
#define X86IM_GEN_CODE_XADD_R1_R2                           0x00C0C00F

#define X86IM_GEN_XADD_MM_RG_BYTE( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_XADD_MM_RG_WORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_XADD_MM_RG_DWORD( io, mode, mm, rg )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_XADD_MM_RG_QWORD( io, mm, rg )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XADD_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_XADD_R1_R2_BYTE( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XADD_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XADD_R1_R2_WORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XADD_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XADD_R1_R2_DWORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XADD_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XADD_R1_R2_QWORD( io, r1, r2 )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XADD_R1_R2, X86IM_GEN_R2_R1( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_XCHG_MM_RG                           0x00000086
#define X86IM_GEN_CODE_XCHG_R1_R2                           0x0000C086
#define X86IM_GEN_CODE_XCHG_AC_RG                           0x00000091

#define X86IM_GEN_XCHG_MM_RG_BYTE( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XCHG_MM_RG, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_XCHG_MM_RG_WORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XCHG_MM_RG, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_XCHG_MM_RG_DWORD( io, mode, mm, rg )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XCHG_MM_RG, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_XCHG_MM_RG_QWORD( io, mm, rg )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XCHG_MM_RG, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_XCHG_R1_R2_BYTE( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XCHG_R1_R2_WORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XCHG_R1_R2_DWORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XCHG_R1_R2_QWORD( io, r1, r2 )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XCHG_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_XCHG_AC_RG_WORD( io, mode, rg )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XCHG_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_XCHG_AC_RG_DWORD( io, mode, rg )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XCHG_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )
#define X86IM_GEN_XCHG_AC_RG_QWORD( io, rg )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XCHG_AC_RG, X86IM_GEN_AC_RG( rg ), 0, 0, 0 )

#define X86IM_GEN_CODE_XOR_MM_RG                            0x00000030
#define X86IM_GEN_CODE_XOR_R2_R1                            0x0000C030
#define X86IM_GEN_CODE_XOR_RG_MM                            0x00000032
#define X86IM_GEN_CODE_XOR_R1_R2                            0x0000C032
#define X86IM_GEN_CODE_XOR_RG_IM                            0x0000F080
#define X86IM_GEN_CODE_XOR_AC_IM                            0x00000034
#define X86IM_GEN_CODE_XOR_MM_IM                            0x00003080

#define X86IM_GEN_XOR_MM_RG_BYTE( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XOR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_XOR_MM_RG_WORD( io, mode, mm, rg )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XOR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_XOR_MM_RG_DWORD( io, mode, mm, rg )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XOR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )
#define X86IM_GEN_XOR_MM_RG_QWORD( io, mm, rg )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XOR_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_XOR_R2_R1_BYTE( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XOR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_XOR_R2_R1_WORD( io, mode, r2, r1 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XOR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_XOR_R2_R1_DWORD( io, mode, r2, r1 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XOR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )
#define X86IM_GEN_XOR_R2_R1_QWORD( io, r2, r1 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XOR_R2_R1, X86IM_GEN_R2_R1( r2, r1 ), 0, 0, 0 )

#define X86IM_GEN_XOR_RG_MM_BYTE( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XOR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_XOR_RG_MM_WORD( io, mode, rg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XOR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_XOR_RG_MM_DWORD( io, mode, rg, mm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XOR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )
#define X86IM_GEN_XOR_RG_MM_QWORD( io, rg, mm )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XOR_RG_MM, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_XOR_R1_R2_BYTE( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XOR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XOR_R1_R2_WORD( io, mode, r1, r2 )        x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XOR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XOR_R1_R2_DWORD( io, mode, r1, r2 )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XOR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_XOR_R1_R2_QWORD( io, r1, r2 )             x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XOR_R1_R2, X86IM_GEN_R1_R2( r1, r2 ), 0, 0, 0 )

#define X86IM_GEN_XOR_MM_IM_BYTE( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm ) 
#define X86IM_GEN_XOR_MM_IM_WORD( io, mode, mm, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm )
#define X86IM_GEN_XOR_MM_IM_DWORD( io, mode, mm, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm )
#define X86IM_GEN_XOR_MM_IM_QWORD( io, mm, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm )

#define X86IM_GEN_XOR_MM_IM_SBYTE( io, mm, imm8 )           x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_XOR_MM_IM_SWORD( io, mode, mm, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_XOR_MM_IM_SDWORD( io, mode, mm, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm8 )
#define X86IM_GEN_XOR_MM_IM_SQWORD( io, mm, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_MM_IM, 0, mm, imm8 )

#define X86IM_GEN_XOR_RG_IM_BYTE( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_XOR_RG_IM_WORD( io, mode, rg, imm )       x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_XOR_RG_IM_DWORD( io, mode, rg, imm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )
#define X86IM_GEN_XOR_RG_IM_QWORD( io, rg, imm )            x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm )

#define X86IM_GEN_XOR_RG_IM_SBYTE( io, rg8, imm8 )          x86im_gen( io, X86IM_IO_MODE_32BIT|X86IM_GEN_OAT_NPO_B|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg8 ), 0, 0, imm8 )
#define X86IM_GEN_XOR_RG_IM_SWORD( io, mode, rg, imm8 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  
#define X86IM_GEN_XOR_RG_IM_SDWORD( io, mode, rg, imm8 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )
#define X86IM_GEN_XOR_RG_IM_SQWORD( io, rg, imm8 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q|X86IM_GEN_OAT_SIGN, X86IM_GEN_CODE_XOR_RG_IM, X86IM_GEN_RG_IM( rg ), 0, 0, imm8 )  

#define X86IM_GEN_XOR_AC_IM_BYTE( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_B, X86IM_GEN_CODE_XOR_AC_IM, 0, 0, 0, imm )     
#define X86IM_GEN_XOR_AC_IM_WORD( io, mode, imm )           x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_XOR_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_XOR_AC_IM_DWORD( io, mode, imm )          x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_XOR_AC_IM, 0, 0, 0, imm )
#define X86IM_GEN_XOR_AC_IM_QWORD( io, imm )                x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_XOR_AC_IM, 0, 0, 0, imm )

#define X86IM_GEN_CODE_CMOVCC_RG_MM                         0x0000400F
#define X86IM_GEN_CODE_CMOVCC_R1_R2                         0x00C0400F

#define X86IM_GEN_CMOVO_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_O, rg ), mm, 0 )
#define X86IM_GEN_CMOVO_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_O, rg ), mm, 0 )
#define X86IM_GEN_CMOVO_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_O, rg ), mm, 0 )
#define X86IM_GEN_CMOVNO_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NO, rg ), mm, 0 )
#define X86IM_GEN_CMOVNO_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NO, rg ), mm, 0 )
#define X86IM_GEN_CMOVNO_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NO, rg ), mm, 0 )
#define X86IM_GEN_CMOVB_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_B, rg ), mm, 0 )
#define X86IM_GEN_CMOVB_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_B, rg ), mm, 0 )
#define X86IM_GEN_CMOVB_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_B, rg ), mm, 0 )
#define X86IM_GEN_CMOVC_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_C, rg ), mm, 0 )
#define X86IM_GEN_CMOVC_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_C, rg ), mm, 0 )
#define X86IM_GEN_CMOVC_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_C, rg ), mm, 0 )
#define X86IM_GEN_CMOVNAE_RG_MM_WORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NAE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNAE_RG_MM_DWORD( io, mode, rg, mm )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NAE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNAE_RG_MM_QWORD( io, rg, mm )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NAE, rg ), mm, 0 )
#define X86IM_GEN_CMOVAE_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_AE, rg ), mm, 0 )
#define X86IM_GEN_CMOVAE_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_AE, rg ), mm, 0 )
#define X86IM_GEN_CMOVAE_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_AE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNB_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NB, rg ), mm, 0 )
#define X86IM_GEN_CMOVNB_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NB, rg ), mm, 0 )
#define X86IM_GEN_CMOVNB_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NB, rg ), mm, 0 )
#define X86IM_GEN_CMOVNC_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NC, rg ), mm, 0 )
#define X86IM_GEN_CMOVNC_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NC, rg ), mm, 0 )
#define X86IM_GEN_CMOVNC_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NC, rg ), mm, 0 )
#define X86IM_GEN_CMOVE_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_E, rg ), mm, 0 )
#define X86IM_GEN_CMOVE_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_E, rg ), mm, 0 )
#define X86IM_GEN_CMOVE_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_E, rg ), mm, 0 )
#define X86IM_GEN_CMOVZ_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_Z, rg ), mm, 0 )
#define X86IM_GEN_CMOVZ_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_Z, rg ), mm, 0 )
#define X86IM_GEN_CMOVZ_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_Z, rg ), mm, 0 )
#define X86IM_GEN_CMOVNE_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNE_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNE_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNZ_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NZ, rg ), mm, 0 )
#define X86IM_GEN_CMOVNZ_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NZ, rg ), mm, 0 )
#define X86IM_GEN_CMOVNZ_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NZ, rg ), mm, 0 )
#define X86IM_GEN_CMOVBE_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_BE, rg ), mm, 0 )
#define X86IM_GEN_CMOVBE_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_BE, rg ), mm, 0 )
#define X86IM_GEN_CMOVBE_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_BE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNA_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NA, rg ), mm, 0 )
#define X86IM_GEN_CMOVNA_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NA, rg ), mm, 0 )
#define X86IM_GEN_CMOVNA_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NA, rg ), mm, 0 )
#define X86IM_GEN_CMOVA_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_A, rg ), mm, 0 )
#define X86IM_GEN_CMOVA_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_A, rg ), mm, 0 )
#define X86IM_GEN_CMOVA_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_A, rg ), mm, 0 )
#define X86IM_GEN_CMOVNBE_RG_MM_WORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NBE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNBE_RG_MM_DWORD( io, mode, rg, mm )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NBE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNBE_RG_MM_QWORD( io, rg, mm )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NBE, rg ), mm, 0 )
#define X86IM_GEN_CMOVS_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_S, rg ), mm, 0 )
#define X86IM_GEN_CMOVS_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_S, rg ), mm, 0 )
#define X86IM_GEN_CMOVS_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_S, rg ), mm, 0 )
#define X86IM_GEN_CMOVNS_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NS, rg ), mm, 0 )
#define X86IM_GEN_CMOVNS_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NS, rg ), mm, 0 )
#define X86IM_GEN_CMOVNS_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NS, rg ), mm, 0 )
#define X86IM_GEN_CMOVP_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_P, rg ), mm, 0 )
#define X86IM_GEN_CMOVP_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_P, rg ), mm, 0 )
#define X86IM_GEN_CMOVP_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_P, rg ), mm, 0 )
#define X86IM_GEN_CMOVPE_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_PE, rg ), mm, 0 )
#define X86IM_GEN_CMOVPE_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_PE, rg ), mm, 0 )
#define X86IM_GEN_CMOVPE_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_PE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNP_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NP, rg ), mm, 0 )
#define X86IM_GEN_CMOVNP_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NP, rg ), mm, 0 )
#define X86IM_GEN_CMOVNP_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NP, rg ), mm, 0 )
#define X86IM_GEN_CMOVPO_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_PO, rg ), mm, 0 )
#define X86IM_GEN_CMOVPO_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_PO, rg ), mm, 0 )
#define X86IM_GEN_CMOVPO_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_PO, rg ), mm, 0 )
#define X86IM_GEN_CMOVL_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_L, rg ), mm, 0 )
#define X86IM_GEN_CMOVL_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_L, rg ), mm, 0 )
#define X86IM_GEN_CMOVL_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_L, rg ), mm, 0 )
#define X86IM_GEN_CMOVNGE_RG_MM_WORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NGE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNGE_RG_MM_DWORD( io, mode, rg, mm )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NGE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNGE_RG_MM_QWORD( io, rg, mm )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NGE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNL_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NL, rg ), mm, 0 )
#define X86IM_GEN_CMOVNL_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NL, rg ), mm, 0 )
#define X86IM_GEN_CMOVNL_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NL, rg ), mm, 0 )
#define X86IM_GEN_CMOVGE_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_GE, rg ), mm, 0 )
#define X86IM_GEN_CMOVGE_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_GE, rg ), mm, 0 )
#define X86IM_GEN_CMOVGE_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_GE, rg ), mm, 0 )
#define X86IM_GEN_CMOVLE_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_LE, rg ), mm, 0 )
#define X86IM_GEN_CMOVLE_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_LE, rg ), mm, 0 )
#define X86IM_GEN_CMOVLE_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_LE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNG_RG_MM_WORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NG, rg ), mm, 0 )
#define X86IM_GEN_CMOVNG_RG_MM_DWORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NG, rg ), mm, 0 )
#define X86IM_GEN_CMOVNG_RG_MM_QWORD( io, rg, mm )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NG, rg ), mm, 0 )
#define X86IM_GEN_CMOVNLE_RG_MM_WORD( io, mode, rg, mm )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NLE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNLE_RG_MM_DWORD( io, mode, rg, mm )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NLE, rg ), mm, 0 )
#define X86IM_GEN_CMOVNLE_RG_MM_QWORD( io, rg, mm )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_NLE, rg ), mm, 0 )
#define X86IM_GEN_CMOVG_RG_MM_WORD( io, mode, rg, mm )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_G, rg ), mm, 0 )
#define X86IM_GEN_CMOVG_RG_MM_DWORD( io, mode, rg, mm )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_G, rg ), mm, 0 )
#define X86IM_GEN_CMOVG_RG_MM_QWORD( io, rg, mm )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_RG_MM, X86IM_GEN_TTTN_RG_MM( X86IM_IO_TN_G, rg ), mm, 0 )

#define X86IM_GEN_CMOVO_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_O, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVO_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_O, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVO_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_O, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNO_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NO, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNO_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NO, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNO_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NO, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVB_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_B, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVB_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_B, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVB_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_B, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVC_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_C, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVC_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_C, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVC_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_C, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNAE_R1_R2_WORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NAE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNAE_R1_R2_DWORD( io, mode, r1, r2 )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NAE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNAE_R1_R2_QWORD( io, r1, r2 )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NAE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVAE_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_AE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVAE_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_AE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVAE_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_AE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNB_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NB, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNB_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NB, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNB_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NB, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNC_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NC, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNC_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NC, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNC_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NC, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVE_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_E, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVE_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_E, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVE_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_E, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVZ_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_Z, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVZ_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_Z, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVZ_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_Z, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNE_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNE_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNE_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNZ_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NZ, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNZ_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NZ, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNZ_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NZ, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVBE_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_BE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVBE_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_BE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVBE_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_BE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNA_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NA, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNA_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NA, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNA_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NA, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVA_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_A, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVA_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_A, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVA_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_A, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNBE_R1_R2_WORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NBE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNBE_R1_R2_DWORD( io, mode, r1, r2 )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NBE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNBE_R1_R2_QWORD( io, r1, r2 )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NBE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVS_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_S, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVS_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_S, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVS_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_S, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNS_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NS, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNS_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NS, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNS_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NS, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVP_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_P, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVP_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_P, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVP_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_P, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVPE_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_PE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVPE_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_PE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVPE_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_PE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNP_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NP, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNP_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NP, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNP_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NP, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVPO_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_PO, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVPO_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_PO, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVPO_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_PO, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVL_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_L, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVL_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_L, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVL_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_L, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNGE_R1_R2_WORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NGE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNGE_R1_R2_DWORD( io, mode, r1, r2 )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NGE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNGE_R1_R2_QWORD( io, r1, r2 )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NGE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNL_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NL, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNL_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NL, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNL_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NL, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVGE_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_GE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVGE_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_GE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVGE_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_GE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVLE_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_LE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVLE_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_LE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVLE_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_LE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNG_R1_R2_WORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NG, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNG_R1_R2_DWORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NG, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNG_R1_R2_QWORD( io, r1, r2 )          x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NG, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNLE_R1_R2_WORD( io, mode, r1, r2 )    x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NLE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNLE_R1_R2_DWORD( io, mode, r1, r2 )   x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NLE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVNLE_R1_R2_QWORD( io, r1, r2 )         x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_NLE, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVG_R1_R2_WORD( io, mode, r1, r2 )      x86im_gen( io, mode|X86IM_GEN_OAT_NPO_W, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_G, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVG_R1_R2_DWORD( io, mode, r1, r2 )     x86im_gen( io, mode|X86IM_GEN_OAT_NPO_D, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_G, r1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CMOVG_R1_R2_QWORD( io, r1, r2 )           x86im_gen( io, X86IM_IO_MODE_64BIT|X86IM_GEN_OAT_NPO_Q, X86IM_GEN_CODE_CMOVCC_R1_R2, X86IM_GEN_TTTN_R1_R2( X86IM_IO_TN_G, r1, r2 ), 0, 0, 0 )

// FPU

#define X86IM_GEN_CODE_F2XM1                            0x0000F0D9
#define X86IM_GEN_F2XM1( io, mode )                     x86im_gen( io, mode, X86IM_GEN_CODE_F2XM1, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FABS                             0x0000E1D9
#define X86IM_GEN_FABS( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FABS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FBLD                             0x000020DF
#define X86IM_GEN_FBLD( io, mode, mm )                  x86im_gen( io, mode, X86IM_GEN_CODE_FBLD, 0, mm, 0 )

#define X86IM_GEN_CODE_FBSTP                            0x000030DF
#define X86IM_GEN_FBSTP( io, mode, mm )                 x86im_gen( io, mode, X86IM_GEN_CODE_FBSTP, 0, mm, 0 )

#define X86IM_GEN_CODE_FCHS                             0x0000E0D9
#define X86IM_GEN_FCHS( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FCHS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FNCLEX                           0x0000E2DB
#define X86IM_GEN_FNCLEX( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FNCLEX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FCOMPP                           0x0000D9DE
#define X86IM_GEN_FCOMPP( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FCOMPP, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FCOMIP                           0x0000F0DF
#define X86IM_GEN_FCOMIP( io, mode, stx )               x86im_gen( io, mode, X86IM_GEN_CODE_FCOMIP, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FCOS                             0x0000FFD9
#define X86IM_GEN_FCOS( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FCOS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FDECSTP                          0x0000F6D9
#define X86IM_GEN_FDECSTP( io, mode )                   x86im_gen( io, mode, X86IM_GEN_CODE_FDECSTP, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FFREE                            0x0000C0DD
#define X86IM_GEN_FFREE( io, mode, stx )                x86im_gen( io, mode, X86IM_GEN_CODE_FFREE, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FINCSTP                          0x0000F7D9
#define X86IM_GEN_FINCSTP( io, mode )                   x86im_gen( io, mode, X86IM_GEN_CODE_FINCSTP, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FNINIT                           0x0000E3DB
#define X86IM_GEN_FNINIT( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FNINIT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FLD1                             0x0000E8D9
#define X86IM_GEN_FLD1( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FLD1, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FLDCW                            0x000028D9
#define X86IM_GEN_FLDCW( io, mode, mm )                 x86im_gen( io, mode, X86IM_GEN_CODE_FLDCW, 0, mm, 0 )

#define X86IM_GEN_CODE_FLDENV                           0x000020D9
#define X86IM_GEN_FLDENV( io, mode, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_FLDENV, 0, mm, 0 )

#define X86IM_GEN_CODE_FLDL2E                           0x0000EAD9
#define X86IM_GEN_FLDL2E( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FLDL2E, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FLDL2T                           0x0000E9D9
#define X86IM_GEN_FLDL2T( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FLDL2T, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FLDLG2                           0x0000ECD9
#define X86IM_GEN_FLDLG2( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FLDLG2, 0, 0, 0, 0 )
    
#define X86IM_GEN_CODE_FLDLN2                           0x0000EDD9
#define X86IM_GEN_FLDLN2( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FLDLN2, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FLDPI                            0x0000EBD9
#define X86IM_GEN_FLDPI( io, mode )                     x86im_gen( io, mode, X86IM_GEN_CODE_FLDPI, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FLDZ                             0x0000EED9
#define X86IM_GEN_FLDZ( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FLDZ, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FNOP                             0x0000D0D9
#define X86IM_GEN_FNOP( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FNOP, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FPATAN                           0x0000F3D9
#define X86IM_GEN_FPATAN( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FPATAN, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FPREM                            0x0000F5D9
#define X86IM_GEN_FPREM( io, mode )                     x86im_gen( io, mode, X86IM_GEN_CODE_FPREM, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FPREM1                           0x0000F5D9
#define X86IM_GEN_FPREM1( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FPREM1, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FPTAN                            0x0000F2D9
#define X86IM_GEN_FPTAN( io, mode )                     x86im_gen( io, mode, X86IM_GEN_CODE_FPTAN, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FRNDINT                          0x0000FCD9
#define X86IM_GEN_FRNDINT( io, mode )                   x86im_gen( io, mode, X86IM_GEN_CODE_FRNDINT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FRSTOR                           0x000020DD
#define X86IM_GEN_FRSTOR( io, mode, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_FRSTOR, 0, mm, 0 )

#define X86IM_GEN_CODE_FNSAVE                           0x000030DD
#define X86IM_GEN_FNSAVE( io, mode, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_FNSAVE, 0, mm, 0 )

#define X86IM_GEN_CODE_FSCALE                           0x0000FDD9
#define X86IM_GEN_FSCALE( io, mode )                    x86im_gen( io, mode, X86IM_GEN_CODE_FSCALE, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FSIN                             0x0000FED9        
#define X86IM_GEN_FSIN( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FSIN, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FSINCOS                          0x0000FBD9
#define X86IM_GEN_FSINCOS( io, mode )                   x86im_gen( io, mode, X86IM_GEN_CODE_FSINCOS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FSQRT                            0x0000FAD9
#define X86IM_GEN_FSQRT( io, mode )                     x86im_gen( io, mode, X86IM_GEN_CODE_FSQRT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FNSTCW                           0x000038D9
#define X86IM_GEN_FNSTCW( io, mode, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_FNSTCW, 0, mm, 0 )

#define X86IM_GEN_CODE_FNSTENV                          0x000030D9
#define X86IM_GEN_FNSTENV( io, mode, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_FNSTENV, 0, mm, 0 )

#define X86IM_GEN_CODE_FTST                             0x0000E4D9          
#define X86IM_GEN_FTST( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FTST, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FUCOM_STX                        0x0000E0DD    
#define X86IM_GEN_FUCOM_STX( io, mode, stx )            x86im_gen( io, mode, X86IM_GEN_CODE_FUCOM_STX, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FUCOMP_STX                       0x0000E8DD   
#define X86IM_GEN_FUCOMP_STX( io, mode, stx )           x86im_gen( io, mode, X86IM_GEN_CODE_FUCOMP_STX, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FUCOMPP                          0x0000E9DA       
#define X86IM_GEN_FUCOMPP( io, mode )                   x86im_gen( io, mode, X86IM_GEN_CODE_FUCOMPP, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FUCOMI_ST0_STX                   0x0000E8DB
#define X86IM_GEN_FUCOMI_ST0_STX( io, mode, stx )       x86im_gen( io, mode, X86IM_GEN_CODE_FUCOMI_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FUCOMIP                          0x0000E8DF       
#define X86IM_GEN_FUCOMIP( io, mode, stx )              x86im_gen( io, mode, X86IM_GEN_CODE_FUCOMIP, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FXAM                             0x0000E5D9         
#define X86IM_GEN_FXAM( io, mode )                      x86im_gen( io, mode, X86IM_GEN_CODE_FXAM, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FXCH                             0x0000C8D9                            
#define X86IM_GEN_FXCH( io, mode, stx )                 x86im_gen( io, mode, X86IM_GEN_CODE_FXCH, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FXTRACT                          0x0000F4D9                         
#define X86IM_GEN_FXTRACT( io, mode )                   x86im_gen( io, mode, X86IM_GEN_CODE_FXTRACT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FYL2X                            0x0000F1D9                          
#define X86IM_GEN_FYL2X( io, mode )                     x86im_gen( io, mode, X86IM_GEN_CODE_FYL2X, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FYL2XP1                          0x0000F9D9                      
#define X86IM_GEN_FYL2XP1( io, mode )                   x86im_gen( io, mode, X86IM_GEN_CODE_FYL2XP1, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FXSAVE                           0x0000AE0F
#define X86IM_GEN_FXSAVE( io, mode, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_FXSAVE, 0, mm, 0 )

#define X86IM_GEN_CODE_FXRSTOR                          0x0008AE0F
#define X86IM_GEN_FXRSTOR( io, mode, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_FXRSTOR, 0, mm, 0 )

#define X86IM_GEN_CODE_FFREEP                           0x0000C0DF                          
#define X86IM_GEN_FFREEP( io, mode, stx )               x86im_gen( io, mode, X86IM_GEN_CODE_FFREEP, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FXCH4                            0x0000C8DD
#define X86IM_GEN_FXCH4( io, mode, stx )                x86im_gen( io, mode, X86IM_GEN_CODE_FXCH4, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FXCH7                            0x0000C8DF
#define X86IM_GEN_FXCH7( io, mode, stx )                x86im_gen( io, mode, X86IM_GEN_CODE_FXCH7, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FADDP_STX_ST0                    0x0000C0DE
#define X86IM_GEN_FADDP_STX_ST0( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FADDP_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FDIVP_STX_ST0                    0x0000F8DE
#define X86IM_GEN_FDIVP_STX_ST0( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FDIVP_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FDIVRP_STX_ST0                   0x0000F0DE
#define X86IM_GEN_FDIVRP_STX_ST0( io, mode, stx )       x86im_gen( io, mode, X86IM_GEN_CODE_FDIVRP_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FMULP_STX_ST0                    0x0000C8DE
#define X86IM_GEN_FMULP_STX_ST0( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FMULP_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FSUBP_STX_ST0                    0x0000E8DE
#define X86IM_GEN_FSUBP_STX_ST0( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FSUBP_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FSUBRP_STX_ST0                   0x0000E0DE
#define X86IM_GEN_FSUBRP_STX_ST0( io, mode, stx )       x86im_gen( io, mode, X86IM_GEN_CODE_FSUBRP_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FCOMI_ST0_STX                    0x0000F0DB
#define X86IM_GEN_FCOMI_ST0_STX( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FCOMI_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FADD_MM32FP                      0x000000D8
#define X86IM_GEN_CODE_FADD_MM64FP                      0x000000DC
#define X86IM_GEN_CODE_FADD_ST0_STX                     0x0000C0D8
#define X86IM_GEN_CODE_FADD_STX_ST0                     0x0000C0DC

#define X86IM_GEN_FADD_MM32FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FADD_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FADD_MM64FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FADD_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FADD_ST0_STX( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FADD_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FADD_STX_ST0( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FADD_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FCOM_MM32FP                      0x000010D8                  
#define X86IM_GEN_CODE_FCOM_MM64FP                      0x000010DC                  
#define X86IM_GEN_CODE_FCOM_STX                         0x0000D0D8                
#define X86IM_GEN_CODE_FCOM2_STX_ST0                    0x0000D0DC                      

#define X86IM_GEN_FCOM_MM32FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FCOM_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FCOM_MM64FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FCOM_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FCOM_STX( io, mode, stx )             x86im_gen( io, mode, X86IM_GEN_CODE_FCOM_STX, X86IM_GEN_STX( stx ), 0, 0 , 0 )
#define X86IM_GEN_FCOM2_STX_ST0( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FCOM2_STX_ST0, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FCOMP_MM32FP                     0x000018D8
#define X86IM_GEN_CODE_FCOMP_MM64FP                     0x000018DC
#define X86IM_GEN_CODE_FCOMP_STX                        0x0000D8D8
#define X86IM_GEN_CODE_FCOMP3                           0x0000D8DC
#define X86IM_GEN_CODE_FCOMP5                           0x0000D0DE

#define X86IM_GEN_FCOMP_MM32FP( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FCOMP_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FCOMP_MM64FP( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FCOMP_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FCOMP_STX( io, mode, stx )            x86im_gen( io, mode, X86IM_GEN_CODE_FCOMP_STX, X86IM_GEN_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCOMP3( io, mode, stx )               x86im_gen( io, mode, X86IM_GEN_CODE_FCOMP3, X86IM_GEN_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCOMP5( io, mode, stx )               x86im_gen( io, mode, X86IM_GEN_CODE_FCOMP5, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FDIV_MM32FP                      0x000030D8                
#define X86IM_GEN_CODE_FDIV_MM64FP                      0x000030DC           
#define X86IM_GEN_CODE_FDIV_ST0_STX                     0x0000F0D8              
#define X86IM_GEN_CODE_FDIV_STX_ST0                     0x0000F8DC

#define X86IM_GEN_FDIV_MM32FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FDIV_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FDIV_MM64FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FDIV_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FDIV_ST0_STX( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FDIV_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FDIV_STX_ST0( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FDIV_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FDIVR_MM32FP                     0x000038D8                    
#define X86IM_GEN_CODE_FDIVR_MM64FP                     0x000038DC             
#define X86IM_GEN_CODE_FDIVR_ST0_STX                    0x0000F8D8            
#define X86IM_GEN_CODE_FDIVR_STX_ST0                    0x0000F0DC            

#define X86IM_GEN_FDIVR_MM32FP( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FDIVR_MM32FP, 0, mm, 0 )                    
#define X86IM_GEN_FDIVR_MM64FP( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FDIVR_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FDIVR_ST0_STX( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FDIVR_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )               
#define X86IM_GEN_FDIVR_STX_ST0( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FDIVR_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )
    
#define X86IM_GEN_CODE_FIADD_MM16I                      0x000000DE           
#define X86IM_GEN_CODE_FIADD_MM32I                      0x000000DA           

#define X86IM_GEN_FIADD_MM16I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FIADD_MM16I, 0, mm, 0 )
#define X86IM_GEN_FIADD_MM32I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FIADD_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FICOM_MM16I                      0x000010DE                
#define X86IM_GEN_CODE_FICOM_MM32I                      0x000010DA            

#define X86IM_GEN_FICOM_MM16I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FICOM_MM16I, 0, mm, 0 )
#define X86IM_GEN_FICOM_MM32I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FICOM_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FICOMP_MM16I                     0x000018DE
#define X86IM_GEN_CODE_FICOMP_MM32I                     0x000018DA

#define X86IM_GEN_FICOMP_MM16I( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FICOMP_MM16I, 0, mm, 0 )
#define X86IM_GEN_FICOMP_MM32I( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FICOMP_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FIDIV_MM16I                      0x000030DE              
#define X86IM_GEN_CODE_FIDIV_MM32I                      0x000030DA            

#define X86IM_GEN_FIDIV_MM16I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FIDIV_MM16I, 0, mm, 0 )
#define X86IM_GEN_FIDIV_MM32I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FIDIV_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FIDIVR_MM16I                     0x000038DE          
#define X86IM_GEN_CODE_FIDIVR_MM32I                     0x000038DA         

#define X86IM_GEN_FIDIVR_MM16I( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FIDIVR_MM16I, 0, mm, 0 )                    
#define X86IM_GEN_FIDIVR_MM32I( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FIDIVR_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FILD_MM16I                       0x000000DF
#define X86IM_GEN_CODE_FILD_MM32I                       0x000000DB
#define X86IM_GEN_CODE_FILD_MM64I                       0x000028DF

#define X86IM_GEN_FILD_MM16I( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FILD_MM16I, 0, mm, 0 )                
#define X86IM_GEN_FILD_MM32I( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FILD_MM32I, 0, mm, 0 )
#define X86IM_GEN_FILD_MM64I( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FILD_MM64I, 0, mm, 0 )

#define X86IM_GEN_CODE_FIMUL_MM16I                      0x000008DE
#define X86IM_GEN_CODE_FIMUL_MM32I                      0x000008DA

#define X86IM_GEN_FIMUL_MM16I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FIMUL_MM16I, 0, mm, 0 )
#define X86IM_GEN_FIMUL_MM32I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FIMUL_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FIST_MM16I                       0x000010DF
#define X86IM_GEN_CODE_FIST_MM32I                       0x000010DB

#define X86IM_GEN_FIST_MM16I( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FIST_MM16I, 0, mm, 0 )
#define X86IM_GEN_FIST_MM32I( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FIST_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FISTP_MM16I                      0x000018DF
#define X86IM_GEN_CODE_FISTP_MM32I                      0x000018DB
#define X86IM_GEN_CODE_FISTP_MM64I                      0x000038DF

#define X86IM_GEN_FISTP_MM16I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FISTP_MM16I, 0, mm, 0 )
#define X86IM_GEN_FISTP_MM32I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FISTP_MM32I, 0, mm, 0 )
#define X86IM_GEN_FISTP_MM64I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FISTP_MM64I, 0, mm, 0 )

#define X86IM_GEN_CODE_FISUB_MM16I                      0x000020DE
#define X86IM_GEN_CODE_FISUB_MM32I                      0x000020DA

#define X86IM_GEN_FISUB_MM16I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FISUB_MM16I, 0, mm, 0 )
#define X86IM_GEN_FISUB_MM32I( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FISUB_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FISUBR_MM16I                     0x000028DE                   
#define X86IM_GEN_CODE_FISUBR_MM32I                     0x000028DA                 

#define X86IM_GEN_FISUBR_MM16I( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FISUBR_MM16I, 0, mm, 0 )
#define X86IM_GEN_FISUBR_MM32I( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FISUBR_MM32I, 0, mm, 0 )

#define X86IM_GEN_CODE_FLD_MM32FP                       0x000000D9
#define X86IM_GEN_CODE_FLD_MM64FP                       0x000000DD
#define X86IM_GEN_CODE_FLD_MM80FP                       0x000028DB
#define X86IM_GEN_CODE_FLD_STX                          0x0000C0D9

#define X86IM_GEN_FLD_MM32FP( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FLD_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FLD_MM64FP( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FLD_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FLD_MM80FP( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FLD_MM80FP, 0, mm, 0 )
#define X86IM_GEN_FLD_STX( io, mode, stx )              x86im_gen( io, mode, X86IM_GEN_CODE_FLD_STX, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FMUL_MM32FP                      0x000008D8
#define X86IM_GEN_CODE_FMUL_MM64FP                      0x000008DC
#define X86IM_GEN_CODE_FMUL_ST0_STX                     0x0000C8D8
#define X86IM_GEN_CODE_FMUL_STX_ST0                     0x0000C8DC

#define X86IM_GEN_FMUL_MM32FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FMUL_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FMUL_MM64FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FMUL_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FMUL_ST0_STX( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FMUL_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FMUL_STX_ST0( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FMUL_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0 ,0, 0 )

#define X86IM_GEN_CODE_FST_MM32FP                       0x000010D9
#define X86IM_GEN_CODE_FST_MM64FP                       0x000010DD
#define X86IM_GEN_CODE_FST_STX                          0x0000D0DD

#define X86IM_GEN_FST_MM32FP( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FST_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FST_MM64FP( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FST_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FST_STX( io, mode, stx )              x86im_gen( io, mode, X86IM_GEN_CODE_FST_STX, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FSTP_MM32FP                      0x000018D9
#define X86IM_GEN_CODE_FSTP_MM64FP                      0x000018DD
#define X86IM_GEN_CODE_FSTP_MM80FP                      0x000038DB
#define X86IM_GEN_CODE_FSTP_STX                         0x0000D8DD
#define X86IM_GEN_CODE_FSTP1                            0x0000D8D9
#define X86IM_GEN_CODE_FSTP8                            0x0000D0DF
#define X86IM_GEN_CODE_FSTP9                            0x0000D8DF

#define X86IM_GEN_FSTP_MM32FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FSTP_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FSTP_MM64FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FSTP_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FSTP_MM80FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FSTP_MM80FP, 0, mm, 0 )
#define X86IM_GEN_FSTP_STX( io, mode, stx )             x86im_gen( io, mode, X86IM_GEN_CODE_FSTP_STX, X86IM_GEN_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FSTP1( io, mode, stx )                x86im_gen( io, mode, X86IM_GEN_CODE_FSTP1, X86IM_GEN_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FSTP8( io, mode, stx )                x86im_gen( io, mode, X86IM_GEN_CODE_FSTP8, X86IM_GEN_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FSTP9( io, mode, stx )                x86im_gen( io, mode, X86IM_GEN_CODE_FSTP9, X86IM_GEN_STX( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FNSTSW_MB2                       0x000038DD
#define X86IM_GEN_CODE_FNSTSW_AX                        0x0000E0DF

#define X86IM_GEN_FNSTSW_MB2( io, mode, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_FNSTSW_MB2, 0, mm, 0 )
#define X86IM_GEN_FNSTSW_AX( io, mode )                 x86im_gen( io, mode, X86IM_GEN_CODE_FNSTSW_AX, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_FSUB_MM32FP                      0x000020D8
#define X86IM_GEN_CODE_FSUB_MM64FP                      0x000020DC
#define X86IM_GEN_CODE_FSUB_ST0_STX                     0x0000E0D8
#define X86IM_GEN_CODE_FSUB_STX_ST0                     0x0000E8DC

#define X86IM_GEN_FSUB_MM32FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FSUB_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FSUB_MM64FP( io, mode, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_FSUB_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FSUB_ST0_STX( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FSUB_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FSUB_STX_ST0( io, mode, stx )         x86im_gen( io, mode, X86IM_GEN_CODE_FSUB_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FSUBR_MM32FP                     0x000028D8
#define X86IM_GEN_CODE_FSUBR_MM64FP                     0x000028DC
#define X86IM_GEN_CODE_FSUBR_ST0_STX                    0x0000E8D8
#define X86IM_GEN_CODE_FSUBR_STX_ST0                    0x0000E0DC

#define X86IM_GEN_FSUBR_MM32FP( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FSUBR_MM32FP, 0, mm, 0 )
#define X86IM_GEN_FSUBR_MM64FP( io, mode, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_FSUBR_MM64FP, 0, mm, 0 )
#define X86IM_GEN_FSUBR_ST0_STX( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FSUBR_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FSUBR_STX_ST0( io, mode, stx )        x86im_gen( io, mode, X86IM_GEN_CODE_FSUBR_STX_ST0, X86IM_GEN_STX_ST0( stx ), 0, 0, 0 )

#define X86IM_GEN_CODE_FCMOVB_ST0_STX                   0x0000C0DA
#define X86IM_GEN_CODE_FCMOVE_ST0_STX                   0x0000C8DA
#define X86IM_GEN_CODE_FCMOVBE_ST0_STX                  0x0000D0DA
#define X86IM_GEN_CODE_FCMOVU_ST0_STX                   0x0000D8DA
#define X86IM_GEN_CODE_FCMOVNB_ST0_STX                  0x0000C0DB
#define X86IM_GEN_CODE_FCMOVNE_ST0_STX                  0x0000C8DB
#define X86IM_GEN_CODE_FCMOVNBE_ST0_STX                 0x0000D0DB
#define X86IM_GEN_CODE_FCMOVNU_ST0_STX                  0x0000D8DB

#define X86IM_GEN_FCMOVB_ST0_STX( io, mode, stx )       x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVB_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCMOVE_ST0_STX( io, mode, stx )       x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVE_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCMOVBE_ST0_STX( io, mode, stx )      x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVBE_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCMOVU_ST0_STX( io, mode, stx )       x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVU_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCMOVNB_ST0_STX( io, mode, stx )      x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVNB_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCMOVNE_ST0_STX( io, mode, stx )      x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVNE_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCMOVNBE_ST0_STX( io, mode, stx )     x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVNBE_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )
#define X86IM_GEN_FCMOVNU_ST0_STX( io, mode, stx )      x86im_gen( io, mode, X86IM_GEN_CODE_FCMOVNU_ST0_STX, X86IM_GEN_ST0_STX( stx ), 0, 0, 0 )

// MMX

#define X86IM_GEN_CODE_EMMS                                         0x0000770F                    
#define X86IM_GEN_EMMS( io, mode )                                  x86im_gen( io, mode, X86IM_GEN_CODE_EMMS, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_MOVD_MMXRG_RG                                0x00C06E0F   
#define X86IM_GEN_CODE_MOVD_MMXRG_MM                                0x00006E0F   
#define X86IM_GEN_CODE_MOVD_RG_MMXRG                                0x00C07E0F                      
#define X86IM_GEN_CODE_MOVD_MM_MMXRG                                0x00007E0F   

#define X86IM_GEN_MOVD_MMXRG_RG( io, mode, mxr1, r2 )               x86im_gen( io, mode, X86IM_GEN_CODE_MOVD_MMXRG_RG, X86IM_GEN_MXR1_R2( mxr1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVD_MMXRG_MM( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_MOVD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_MOVD_RG_MMXRG( io, mode, r1, mxr2 )               x86im_gen( io, mode, X86IM_GEN_CODE_MOVD_RG_MMXRG, X86IM_GEN_R1_MXR2( r1, mxr2 ), 0 , 0, 0 )                  
#define X86IM_GEN_MOVD_MM_MMXRG( io, mode, mm, mxrg )               x86im_gen( io, mode, X86IM_GEN_CODE_MOVD_MM_MMXRG, X86IM_GEN_MM_MXRG( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVQ_MMXR1_MMXR2                             0x00C06F0F  
#define X86IM_GEN_CODE_MOVQ_MMXRG_MM                                0x00006F0F  
#define X86IM_GEN_CODE_MOVQ_MMXR2_MMXR1                             0x00C07F0F            
#define X86IM_GEN_CODE_MOVQ_MM_MMXRG                                0x00007F0F  

#define X86IM_GEN_MOVQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )          x86im_gen( io, mode, X86IM_GEN_CODE_MOVQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVQ_MMXRG_MM( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_MOVQ_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_MOVQ_MMXR2_MMXR1( io, mode, mxr1, mxr2 )          x86im_gen( io, mode, X86IM_GEN_CODE_MOVQ_MMXR2_MMXR1, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVQ_MM_MMXRG( io, mode, mm, mxrg )               x86im_gen( io, mode, X86IM_GEN_CODE_MOVQ_MM_MMXRG, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PACKSSDW_MMXR1_MMXR2                         0x00C06B0F   
#define X86IM_GEN_CODE_PACKSSDW_MMXRG_MM                            0x00006B0F   

#define X86IM_GEN_PACKSSDW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_PACKSSDW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PACKSSDW_MMXRG_MM( io, mode, mxrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_PACKSSDW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PACKSSWB_MMXR1_MMXR2                         0x00C0630F    
#define X86IM_GEN_CODE_PACKSSWB_MMXRG_MM                            0x0000630F    

#define X86IM_GEN_PACKSSWB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_PACKSSWB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PACKSSWB_MMXRG_MM( io, mode, mxrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_PACKSSWB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PACKUSWB_MMXR1_MMXR2                         0x00C0670F    
#define X86IM_GEN_CODE_PACKUSWB_MMXRG_MM                            0x0000670F    

#define X86IM_GEN_PACKUSWB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_PACKUSWB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PACKUSWB_MMXRG_MM( io, mode, mxrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_PACKUSWB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PADDX_MMXR1_MMXR2                            0x00C0FC0F  
#define X86IM_GEN_CODE_PADDX_MMXRG_MM                               0x0000FC0F

#define X86IM_GEN_PADDB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDB_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PADDW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDW_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PADDD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PADDX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDD_MMXRG_MM( io, mode, mxrg, mm  )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PADDX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PADDSX_MMXR1_MMXR2                           0x00C0EC0F  
#define X86IM_GEN_CODE_PADDSX_MMXRG_MM                              0x0000EC0F      

#define X86IM_GEN_PADDSB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDSX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDSB_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDSX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PADDSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDSX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDSW_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDSX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PADDUSB_MMXR1_MMXR2                          0x00C0DC0F   
#define X86IM_GEN_CODE_PADDUSB_MMXRG_MM                             0x0000DC0F   

#define X86IM_GEN_PADDUSB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDUSB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDUSB_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDUSB_MMXR1_MMXR2, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PADDUSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDUSB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 ) 
#define X86IM_GEN_PADDUSW_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDUSB_MMXR1_MMXR2, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PAND_MMXR1_MMXR2                             0x00C0DB0F    
#define X86IM_GEN_CODE_PAND_MMXRG_MM                                0x0000DB0F    

#define X86IM_GEN_PAND_MMXR1_MMXR2( io, mode, mxr1, mxr2 )          x86im_gen( io, mode, X86IM_GEN_CODE_PAND_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )       
#define X86IM_GEN_PAND_MMXRG_MM( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_PAND_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PANDN_MMXR1_MMXR2                            0x00C0DF0F      
#define X86IM_GEN_CODE_PANDN_MMXRG_MM                               0x0000DF0F   

#define X86IM_GEN_PANDN_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PANDN_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PANDN_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PANDN_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PCMPEQX_MMXR1_MMXR2                          0x00C0740F              
#define X86IM_GEN_CODE_PCMPEQX_MMXRG_MM                             0x0000740F          

#define X86IM_GEN_PCMPEQB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPEQX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPEQB_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPEQX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PCMPEQW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPEQX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPEQW_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPEQX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PCMPEQD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPEQX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPEQD_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPEQX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PCMPGTX_MMXR1_MMXR2                          0x00C0640F    
#define X86IM_GEN_CODE_PCMPGTX_MMXRG_MM                             0x0000640F    

#define X86IM_GEN_PCMPGTB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPGTX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPGTB_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPGTX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PCMPGTW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPGTX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPGTW_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPGTX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PCMPGTD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPGTX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPGTD_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPGTX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PMADDWD_MMXR1_MMXR2                          0x00C0F50F      
#define X86IM_GEN_CODE_PMADDWD_MMXRG_MM                             0x0000F50F    

#define X86IM_GEN_PMADDWD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode, X86IM_GEN_CODE_PMADDWD_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMADDWD_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_PMADDWD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULHW_MMXR1_MMXR2                           0x00C0E50F  
#define X86IM_GEN_CODE_PMULHW_MMXRG_MM                              0x0000E50F  

#define X86IM_GEN_PMULHW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_PMULHW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULHW_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode, X86IM_GEN_CODE_PMULHW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULLW_MMXR1_MMXR2                           0x00C0D50F         
#define X86IM_GEN_CODE_PMULLW_MMXRG_MM                              0x0000D50F    

#define X86IM_GEN_PMULLW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_PMULLW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULLW_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode, X86IM_GEN_CODE_PMULLW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_POR_MMXR1_MMXR2                              0x00C0EB0F         
#define X86IM_GEN_CODE_POR_MMXRG_MM                                 0x0000EB0F    

#define X86IM_GEN_POR_MMXR1_MMXR2( io, mode, mxr1, mxr2 )           x86im_gen( io, mode, X86IM_GEN_CODE_POR_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_POR_MMXRG_MM( io, mode, mxrg, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_POR_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PSLLW_MMXR1_MMXR2                            0x00C0F10F   
#define X86IM_GEN_CODE_PSLLW_MMXRG_MM                               0x0000F10F   
#define X86IM_GEN_CODE_PSLLW_MMXRG_IMM8                             0x0030710F   

#define X86IM_GEN_PSLLW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSLLW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSLLW_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSLLW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSLLW_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSLLW_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSLLD_MMXR1_MMXR2                            0x00C0F20F    
#define X86IM_GEN_CODE_PSLLD_MMXRG_MM                               0x0000F20F    
#define X86IM_GEN_CODE_PSLLD_MMXRG_IMM8                             0x0030720F    

#define X86IM_GEN_PSLLD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSLLD_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSLLD_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSLLD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSLLD_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSLLD_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSLLQ_MMXR1_MMXR2                            0x00C0F30F    
#define X86IM_GEN_CODE_PSLLQ_MMXRG_MM                               0x0000F30F    
#define X86IM_GEN_CODE_PSLLQ_MMXRG_IMM8                             0x00F0730F    
                          
#define X86IM_GEN_PSLLQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSLLQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSLLQ_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSLLQ_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSLLQ_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSLLQ_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRAW_MMXR1_MMXR2                            0x00C0E10F    
#define X86IM_GEN_CODE_PSRAW_MMXRG_MM                               0x0000E10F                 
#define X86IM_GEN_CODE_PSRAW_MMXRG_IMM8                             0x0020710F    

#define X86IM_GEN_PSRAW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSRAW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRAW_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSRAW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSRAW_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSRAW_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRAD_MMXR1_MMXR2                            0x00C0E20F    
#define X86IM_GEN_CODE_PSRAD_MMXRG_MM                               0x0000E20F    
#define X86IM_GEN_CODE_PSRAD_MMXRG_IMM8                             0x0020720F    
             
#define X86IM_GEN_PSRAD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSRAD_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRAD_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSRAD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSRAD_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSRAD_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRLW_MMXR1_MMXR2                            0x00C0D10F    
#define X86IM_GEN_CODE_PSRLW_MMXRG_MM                               0x0000D10F    
#define X86IM_GEN_CODE_PSRLW_MMXRG_IMM8                             0x0010710F    

#define X86IM_GEN_PSRLW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSRLW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRLW_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSRLW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSRLW_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSRLW_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRLD_MMXR1_MMXR2                            0x00C0D20F    
#define X86IM_GEN_CODE_PSRLD_MMXRG_MM                               0x0000D20F    
#define X86IM_GEN_CODE_PSRLD_MMXRG_IMM8                             0x0010720F    

#define X86IM_GEN_PSRLD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSRLD_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRLD_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSRLD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSRLD_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSRLD_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRLQ_MMXR1_MMXR2                            0x00C0D30F    
#define X86IM_GEN_CODE_PSRLQ_MMXRG_MM                               0x0000D30F    
#define X86IM_GEN_CODE_PSRLQ_MMXRG_IMM8                             0x00D0730F    

#define X86IM_GEN_PSRLQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSRLQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRLQ_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PSRLQ_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSRLQ_MMXRG_IMM8( io, mode, mxrg, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_PSRLQ_MMXRG_IMM8, mxrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSUBX_MMXR1_MMXR2                            0x00C0F80F    
#define X86IM_GEN_CODE_PSUBX_MMXRG_MM                               0x0000F80F    

#define X86IM_GEN_PSUBB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBB_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSUBW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBW_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSUBD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSUBX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBD_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSUBX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PSUBSX_MMXR1_MMXR2                           0x00C0E80F    
#define X86IM_GEN_CODE_PSUBSX_MMXRG_MM                              0x0000E80F    

#define X86IM_GEN_PSUBSB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBSX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBSB_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBSX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSUBSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBSX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBSW_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBSX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PSUBUSX_MMXR1_MMXR2                          0x00C0D80F   
#define X86IM_GEN_CODE_PSUBUSX_MMXRG_MM                             0x0000D80F   

#define X86IM_GEN_PSUBUSB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBUSX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBUSB_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBUSX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSUBUSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBUSX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBUSW_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBUSX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PUNPCKHXX_MMXR1_MMXR2                        0x00C0680F   
#define X86IM_GEN_CODE_PUNPCKHXX_MMXRG_MM                           0x0000680F   

#define X86IM_GEN_PUNPCKHBW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKHXX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKHBW_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKHXX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PUNPCKHWD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKHXX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKHWD_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKHXX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PUNPCKHDQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKHXX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKHDQ_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKHXX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PUNPCKLXX_MMXR1_MMXR2                        0x00C0600F    
#define X86IM_GEN_CODE_PUNPCKLXX_MMXRG_MM32                         0x0000600F    

#define X86IM_GEN_PUNPCKLBW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKLXX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKLBW_MMXRG_MM32( io, mode, mxrg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKLXX_MMXRG_MM32, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PUNPCKLWD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKLXX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKLWD_MMXRG_MM32( io, mode, mxrg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKLXX_MMXRG_MM32, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PUNPCKLDQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKLXX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKLDQ_MMXRG_MM32( io, mode, mxrg, mm )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKLXX_MMXRG_MM32, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PXOR_MMXR1_MMXR2                             0x00C0EF0F    
#define X86IM_GEN_CODE_PXOR_MMXRG_MM                                0x0000EF0F    

#define X86IM_GEN_PXOR_MMXR1_MMXR2( io, mode, mxr1, mxr2 )          x86im_gen( io, mode, X86IM_GEN_CODE_PXOR_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PXOR_MMXRG_MM( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_PXOR_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

// 3DNOW                                

#define X86IM_GEN_CODE_PI2FW_MMXR1_MMXR2                        0x0CC00F0F
#define X86IM_GEN_CODE_PI2FW_MMXRG_MM                           0x0C000F0F

#define X86IM_GEN_PI2FW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PI2FW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PI2FW_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PI2FW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PI2FD_MMXR1_MMXR2                        0x0DC00F0F    
#define X86IM_GEN_CODE_PI2FD_MMXRG_MM                           0x0D000F0F 

#define X86IM_GEN_PI2FD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PI2FD_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PI2FD_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PI2FD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PF2IW_MMXR1_MMXR2                        0x1CC00F0F    
#define X86IM_GEN_CODE_PF2IW_MMXRG_MM                           0x1C000F0F 

#define X86IM_GEN_PF2IW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PF2IW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )  
#define X86IM_GEN_PF2IW_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PF2IW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PF2ID_MMXR1_MMXR2                        0x1DC00F0F
#define X86IM_GEN_CODE_PF2ID_MMXRG_MM                           0x1D000F0F

#define X86IM_GEN_PF2ID_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PF2ID_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PF2ID_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PF2ID_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFNACC_MMXR1_MMXR2                       0x8AC00F0F
#define X86IM_GEN_CODE_PFNACC_MMXRG_MM                          0x8A000F0F

#define X86IM_GEN_PFNACC_MMXR1_MMXR2( io, mode, mxr1, mxr2 )    x86im_gen( io, mode, X86IM_GEN_CODE_PFNACC_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFNACC_MMXRG_MM( io, mode, mxrg, mm )         x86im_gen( io, mode, X86IM_GEN_CODE_PFNACC_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFPNACC_MMXR1_MMXR2                      0x8EC00F0F
#define X86IM_GEN_CODE_PFPNACC_MMXRG_MM                         0x8E000F0F

#define X86IM_GEN_PFPNACC_MMXR1_MMXR2( io, mode, mxr1, mxr2 )   x86im_gen( io, mode, X86IM_GEN_CODE_PFPNACC_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFPNACC_MMXRG_MM( io, mode, mxrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_PFPNACC_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFCMPGE_MMXR1_MMXR2                      0x90C00F0F
#define X86IM_GEN_CODE_PFCMPGE_MMXRG_MM                         0x90000F0F

#define X86IM_GEN_PFCMPGE_MMXR1_MMXR2( io, mode, mxr1, mxr2 )   x86im_gen( io, mode, X86IM_GEN_CODE_PFCMPGE_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFCMPGE_MMXRG_MM( io, mode, mxrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_PFCMPGE_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )    

#define X86IM_GEN_CODE_PFMIN_MMXR1_MMXR2                        0x94C00F0F
#define X86IM_GEN_CODE_PFMIN_MMXRG_MM                           0x94000F0F

#define X86IM_GEN_PFMIN_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PFMIN_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFMIN_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PFMIN_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFRCP_MMXR1_MMXR2                        0x96C00F0F
#define X86IM_GEN_CODE_PFRCP_MMXRG_MM                           0x96000F0F

#define X86IM_GEN_PFRCP_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PFRCP_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFRCP_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PFRCP_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFRSQRT_MMXR1_MMXR2                      0x97C00F0F
#define X86IM_GEN_CODE_PFRSQRT_MMXRG_MM                         0x97000F0F

#define X86IM_GEN_PFRSQRT_MMXR1_MMXR2( io, mode, mxr1, mxr2 )   x86im_gen( io, mode, X86IM_GEN_CODE_PFRSQRT_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFRSQRT_MMXRG_MM( io, mode, mxrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_PFRSQRT_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFSUB_MMXR1_MMXR2                        0x9AC00F0F
#define X86IM_GEN_CODE_PFSUB_MMXRG_MM                           0x9A000F0F

#define X86IM_GEN_PFSUB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PFSUB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFSUB_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PFSUB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFADD_MMXR1_MMXR2                        0x9EC00F0F
#define X86IM_GEN_CODE_PFADD_MMXRG_MM                           0x9E000F0F

#define X86IM_GEN_PFADD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PFADD_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFADD_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PFADD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFCMPGT_MMXR1_MMXR2                      0xA0C00F0F
#define X86IM_GEN_CODE_PFCMPGT_MMXRG_MM                         0xA0000F0F

#define X86IM_GEN_PFCMPGT_MMXR1_MMXR2( io, mode, mxr1, mxr2 )   x86im_gen( io, mode, X86IM_GEN_CODE_PFCMPGT_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFCMPGT_MMXRG_MM( io, mode, mxrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_PFCMPGT_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFMAX_MMXR1_MMXR2                        0xA4C00F0F
#define X86IM_GEN_CODE_PFMAX_MMXRG_MM                           0xA4000F0F

#define X86IM_GEN_PFMAX_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PFMAX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFMAX_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PFMAX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFRCPIT1_MMXR1_MMXR2                     0xA6C00F0F
#define X86IM_GEN_CODE_PFRCPIT1_MMXRG_MM                        0xA6000F0F

#define X86IM_GEN_PFRCPIT1_MMXR1_MMXR2( io, mode, mxr1, mxr2 )  x86im_gen( io, mode, X86IM_GEN_CODE_PFRCPIT1_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFRCPIT1_MMXRG_MM( io, mode, mxrg, mm )       x86im_gen( io, mode, X86IM_GEN_CODE_PFRCPIT1_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFRSQIT1_MMXR1_MMXR2                     0xA7C00F0F
#define X86IM_GEN_CODE_PFRSQIT1_MMXRG_MM                        0xA7000F0F

#define X86IM_GEN_PFRSQIT1_MMXR1_MMXR2( io, mode, mxr1, mxr2 )  x86im_gen( io, mode, X86IM_GEN_CODE_PFRSQIT1_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFRSQIT1_MMXRG_MM( io, mode, mxrg, mm )       x86im_gen( io, mode, X86IM_GEN_CODE_PFRSQIT1_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFSUBR_MMXR1_MMXR2                       0xAAC00F0F
#define X86IM_GEN_CODE_PFSUBR_MMXRG_MM                          0xAA000F0F

#define X86IM_GEN_PFSUBR_MMXR1_MMXR2( io, mode, mxr1, mxr2 )    x86im_gen( io, mode, X86IM_GEN_CODE_PFSUBR_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFSUBR_MMXRG_MM( io, mode, mxrg, mm )         x86im_gen( io, mode, X86IM_GEN_CODE_PFSUBR_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFACC_MMXR1_MMXR2                        0xAEC00F0F
#define X86IM_GEN_CODE_PFACC_MMXRG_MM                           0xAE000F0F

#define X86IM_GEN_PFACC_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PFACC_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFACC_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PFACC_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFCMPEQ_MMXR1_MMXR2                      0xB0C00F0F 
#define X86IM_GEN_CODE_PFCMPEQ_MMXRG_MM                         0xB0000F0F

#define X86IM_GEN_PFCMPEQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )   x86im_gen( io, mode, X86IM_GEN_CODE_PFCMPEQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFCMPEQ_MMXRG_MM( io, mode, mxrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_PFCMPEQ_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFMUL_MMXR1_MMXR2                        0xB4C00F0F
#define X86IM_GEN_CODE_PFMUL_MMXRG_MM                           0xB4000F0F

#define X86IM_GEN_PFMUL_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PFMUL_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFMUL_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PFMUL_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PFRCPIT2_MMXR1_MMXR2                     0xB6C00F0F
#define X86IM_GEN_CODE_PFRCPIT2_MMXRG_MM                        0xB6000F0F

#define X86IM_GEN_PFRCPIT2_MMXR1_MMXR2( io, mode, mxr1, mxr2 )  x86im_gen( io, mode, X86IM_GEN_CODE_PFRCPIT2_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PFRCPIT2_MMXRG_MM( io, mode, mxrg, mm )       x86im_gen( io, mode, X86IM_GEN_CODE_PFRCPIT2_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULHRW_MMXR1_MMXR2                      0xB7C00F0F
#define X86IM_GEN_CODE_PMULHRW_MMXRG_MM                         0xB7000F0F

#define X86IM_GEN_PMULHRW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )   x86im_gen( io, mode, X86IM_GEN_CODE_PMULHRW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULHRW_MMXRG_MM( io, mode, mxrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_PMULHRW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PSWAPD_MMXR1_MMXR2                       0xBBC00F0F
#define X86IM_GEN_CODE_PSWAPD_MMXRG_MM                          0xBB000F0F

#define X86IM_GEN_PSWAPD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )    x86im_gen( io, mode, X86IM_GEN_CODE_PSWAPD_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSWAPD_MMXRG_MM( io, mode, mxrg, mm )         x86im_gen( io, mode, X86IM_GEN_CODE_PSWAPD_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PAVGUSB_MMXR1_MMXR2                      0xBFC00F0F
#define X86IM_GEN_CODE_PAVGUSB_MMXRG_MM                         0xBF000F0F

#define X86IM_GEN_PAVGUSB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )   x86im_gen( io, mode, X86IM_GEN_CODE_PAVGUSB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PAVGUSB_MMXRG_MM( io, mode, mxrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_PAVGUSB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

// SSE                                  

#define X86IM_GEN_CODE_MOVMSKPS_R1_XMMR2                        0x00C0500F
#define X86IM_GEN_MOVMSKPS_R1_XMMR2( io, mode, r1, xmr2 )       x86im_gen( io, mode, X86IM_GEN_CODE_MOVMSKPS_R1_XMMR2, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_LDMXCSR_MM32                             0x0010AE0F
#define X86IM_GEN_LDMXCSR_MM32( io, mode, mm )                  x86im_gen( io, mode, X86IM_GEN_CODE_LDMXCSR_MM32, 0, mm, 0 )

#define X86IM_GEN_CODE_STMXCSR_MM32 0x0018AE0F
#define X86IM_GEN_STMXCSR_MM32( io, mode, mm )                  x86im_gen( io, mode, X86IM_GEN_CODE_STMXCSR_MM32, 0, mm, 0 )

#define X86IM_GEN_CODE_MASKMOVQ_MMXR1_MMXR2                     0x0000F70F             
#define X86IM_GEN_MASKMOVQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )  x86im_gen( io, mode, X86IM_GEN_CODE_MASKMOVQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_MOVNTPS_MM_XMMRG                         0x00002B0F             
#define X86IM_GEN_MOVNTPS_MM_XMMRG( io, mode, mm, xmrg )        x86im_gen( io, mode, X86IM_GEN_CODE_MOVNTPS_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVNTQ_MM_MMXRG                          0x0000E70F                
#define X86IM_GEN_MOVNTQ_MM_MMXRG( io, mode, mm, mxrg )         x86im_gen( io, mode, X86IM_GEN_CODE_MOVNTQ_MM_MMXRG, X86IM_GEN_MM_MXRG( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PREFETCHT0                               0x0008180F                  
#define X86IM_GEN_CODE_PREFETCHT1                               0x0010180F                  
#define X86IM_GEN_CODE_PREFETCHT2                               0x0018180F                  
#define X86IM_GEN_CODE_PREFETCHNTA                              0x0018180F                  

#define X86IM_GEN_CODE_SFENCE                                   0x00F8AE0F                    

#define X86IM_GEN_CODE_ADDPS_XMMR1_XMMR2                        0x00C0580F    
#define X86IM_GEN_CODE_ADDPS_XMMRG_MM                           0x0000580F    

#define X86IM_GEN_ADDPS_XMMR1_XMMR2( io, mode, xmr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_ADDPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )    
#define X86IM_GEN_ADDPS_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_ADDPS_XMMR1_XMMR2, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ADDSS_XMMR1_XMMR2                        0x00C0580F                    
#define X86IM_GEN_CODE_ADDSS_XMMRG_MM32                         0x0000580F         

#define X86IM_GEN_ADDSS_XMMR1_XMMR2( io, mode, xmr1, mxr2 )     x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_ADDPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )      
#define X86IM_GEN_ADDSS_XMMRG_MM32( io, mode, xmrg, mm )        x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_ADDPS_XMMR1_XMMR2, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ANDNPS_XMMR1_XMMR2                           0x0000550F              
#define X86IM_GEN_CODE_ANDNPS_XMMRG_MM                              0x0000550F

#define X86IM_GEN_ANDNPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_ANDNPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ANDNPS_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode, X86IM_GEN_CODE_ANDNPS_XMMRG_MM, xmrg, mm, 0 )
    
#define X86IM_GEN_CODE_ANDPS_XMMR1_XMMR2                            0x0000540F           
#define X86IM_GEN_CODE_ANDPS_XMMRG_MM                               0x0000540F

#define X86IM_GEN_ANDPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_ANDPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )                    
#define X86IM_GEN_ANDPS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_ANDPS_XMMRG_MM, xmrg, mm, 0 )   

#define X86IM_GEN_CODE_CMPPS_XMMR1_XMMR2_IMM8                               0x00C0C20F    
#define X86IM_GEN_CODE_CMPPS_XMMRG_MM_IMM8                                  0x0000C20F    

#define X86IM_GEN_CMPPS_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )      x86im_gen( io, mode, X86IM_GEN_CODE_CMPPS_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )             
#define X86IM_GEN_CMPPS_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )           x86im_gen( io, mode, X86IM_GEN_CODE_CMPPS_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )    

#define X86IM_GEN_CODE_CMPSS_XMMR1_XMMR2_IMM8                               0x00C0C20F    
#define X86IM_GEN_CODE_CMPSS_XMMRG_MM32_IMM8                                0x0000C20F    

#define X86IM_GEN_CMPSS_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )      x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CMPSS_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 ) 
#define X86IM_GEN_CMPSS_XMMRG_MM32_IMM8( io, mode, xmrg, mm, imm8 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CMPSS_XMMRG_MM32_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_COMISS_XMMR1_XMMR2                           0x0CC02F0F          
#define X86IM_GEN_CODE_COMISS_XMMRG_MM32                            0x00C02F0F    

#define X86IM_GEN_COMISS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_COMISS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )              
#define X86IM_GEN_COMISS_XMMRG_MM32( io, mode, xmrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_COMISS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTPI2PS_XMMR1_MMXR2                         0x00C02A0F    
#define X86IM_GEN_CODE_CVTPI2PS_XMMRG_MM64                          0x00002A0F       

#define X86IM_GEN_CVTPI2PS_XMMR1_MMXR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_CVTPI2PS_XMMR1_MMXR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )           
#define X86IM_GEN_CVTPI2PS_XMMRG_MM64( io, mode, xmrg, mm )         x86im_gen( io, mode, X86IM_GEN_CODE_CVTPI2PS_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )   

#define X86IM_GEN_CODE_CVTPS2PI_MMXR1_XMMR2                         0x00C02D0F    
#define X86IM_GEN_CODE_CVTPS2PI_MMXRG_MM                            0x00002D0F    

#define X86IM_GEN_CVTPS2PI_MMXR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_CVTPS2PI_MMXR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTPS2PI_MMXRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_CVTPS2PI_MMXRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTSI2SS_XMMR1_R2                            0x00C02A0F   
#define X86IM_GEN_CODE_CVTSI2SS_XMMRG_MM                            0x00002A0F   

#define X86IM_GEN_CVTSI2SS_XMMR1_R2( io, mode, xmr1, r2 )           x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTSI2SS_XMMR1_R2, X86IM_GEN_XMR1_R2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_CVTSI2SS_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTSI2SS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTSS2SI_R1_XMMR2                            0x00C02D0F    
#define X86IM_GEN_CODE_CVTSS2SI_RG_MM32                             0x00002D0F    

#define X86IM_GEN_CVTSS2SI_R1_XMMR2( io, mode, r1, xmr2 )           x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTSS2SI_R1_XMMR2, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTSS2SI_RG_MM32( io, mode, rg, mm )              x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTSS2SI_RG_MM32, X86IM_GEN_RG_MM( rg, mm ), mm, 0 )

#define X86IM_GEN_CODE_CVTTPS2PI_MMXR1_XMMR2                        0x00002C0F    
#define X86IM_GEN_CODE_CVTTPS2PI_MMXRG_MM64                         0x00002C0F    

#define X86IM_GEN_CVTTPS2PI_MMXR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_CVTTPS2PI_MMXR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_CVTTPS2PI_MMXRG_MM64( io, mode, xmrg, mm )        x86im_gen( io, mode, X86IM_GEN_CODE_CVTTPS2PI_MMXRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTTSS2SI_R1_XMMR2                           0x00C02C0F    
#define X86IM_GEN_CODE_CVTTSS2SI_RG_MM32                            0x00002C0F    

#define X86IM_GEN_CVTTSS2SI_R1_XMMR2( io, mode, r1, xmr2 )          x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTTSS2SI_R1_XMMR2, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )            
#define X86IM_GEN_CVTTSS2SI_RG_MM32( io, mode, rg, mm )             x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTTSS2SI_RG_MM32, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_DIVPS_XMMR1_XMMR2                            0x00C05E0F              
#define X86IM_GEN_CODE_DIVPS_XMMRG_MM                               0x00005E0F    

#define X86IM_GEN_DIVPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_DIVPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_DIVPS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_DIVPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_DIVSS_XMMR1_XMMR2                            0x00C05E0F               
#define X86IM_GEN_CODE_DIVSS_XMMRG_MM32                             0x00005E0F    

#define X86IM_GEN_DIVSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_DIVSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_DIVSS_XMMRG_MM32( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_DIVSS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MAXPS_XMMR1_XMMR2                            0x00C05F0F               
#define X86IM_GEN_CODE_MAXPS_XMMRG_MM                               0x00005F0F              

#define X86IM_GEN_MAXPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_MAXPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MAXPS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_MAXPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MAXSS_XMMR1_XMMR2                            0x00C05F0F   
#define X86IM_GEN_CODE_MAXSS_XMMRG_MM32                             0x00005F0F        

#define X86IM_GEN_MAXSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MAXSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MAXSS_XMMRG_MM32( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MAXSS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MINPS_XMMR1_XMMR2                            0x00C05D0F    
#define X86IM_GEN_CODE_MINPS_XMMRG_MM                               0x00005D0F    

#define X86IM_GEN_MINPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_MINPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MINPS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_MINPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MINSS_XMMR1_XMMR2                            0x00C05D0F                 
#define X86IM_GEN_CODE_MINSS_XMMRG_MM32                             0x00005D0F    

#define X86IM_GEN_MINSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MINSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2 ( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MINSS_XMMRG_MM32( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MINSS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVAPS_XMMR1_XMMR2                           0x00C0280F                
#define X86IM_GEN_CODE_MOVAPS_XMMRG_MM                              0x0000280F           
#define X86IM_GEN_CODE_MOVAPS_XMMR2_XMMR1                           0x00C0290F              
#define X86IM_GEN_CODE_MOVAPS_MM_XMMRG                              0x0000290F             

#define X86IM_GEN_MOVAPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_MOVAPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVAPS_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode, X86IM_GEN_CODE_MOVAPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVAPS_XMMR2_XMMR1( io, mode, xmr1, xmr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_MOVAPS_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVAPS_MM_XMMRG( io, mode, mm, xmrg )             x86im_gen( io, mode, X86IM_GEN_CODE_MOVAPS_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVLHPS_XMMR1_XMMR2                          0x00C0160F  

#define X86IM_GEN_MOVLHPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode, X86IM_GEN_CODE_MOVLHPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_MOVHPS_XMMRG_MM64                            0x00C0160F              
#define X86IM_GEN_CODE_MOVHPS_MM64_XMMRG                            0x0000170F   

#define X86IM_GEN_MOVHPS_XMMRG_MM64( io, mode, xmrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_MOVHPS_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVHPS_MM64_XMMRG( io, mode, mm, xmrg )           x86im_gen( io, mode, X86IM_GEN_CODE_MOVHPS_MM64_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVHLPS_XMMR1_XMMR2                          0x00C0120F         

#define X86IM_GEN_CODE_MOVLPS_XMMRG_MM64                            0x0000120F    
#define X86IM_GEN_CODE_MOVLPS_MM64_XMMRG                            0x0000130F    

#define X86IM_GEN_MOVLPS_XMMRG_MM64( io, mode, xmrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_MOVLPS_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVLPS_MM64_XMMRG( io, mode, mm, xmrg )           x86im_gen( io, mode, X86IM_GEN_CODE_MOVLPS_MM64_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVSS_XMMR1_XMMR2                            0x00C0100F       
#define X86IM_GEN_CODE_MOVSS_XMMRG_MM                               0x0000100F                
#define X86IM_GEN_CODE_MOVSS_XMMR2_XMMR1                            0x00C0110F       
#define X86IM_GEN_CODE_MOVSS_MM_XMMRG                               0x0000110F    

#define X86IM_GEN_MOVSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVSS_XMMR2_XMMR1( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSS_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVSS_MM_XMMRG( io, mode, mm, xmrg )              x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSS_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVUPS_XMMR1_XMMR2                           0x00C0100F               
#define X86IM_GEN_CODE_MOVUPS_XMMRG_MM                              0x0000100F                  
#define X86IM_GEN_CODE_MOVUPS_XMMR2_XMMR1                           0x00C0110F             
#define X86IM_GEN_CODE_MOVUPS_MM_XMMRG                              0x0000110F           

#define X86IM_GEN_MOVUPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_MOVUPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVUPS_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode, X86IM_GEN_CODE_MOVUPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVUPS_XMMR2_XMMR1( io, mode, xmr1, xmr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_MOVUPS_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVUPS_MM_XMMRG( io, mode, mm, xmrg )             x86im_gen( io, mode, X86IM_GEN_CODE_MOVUPS_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MULPS_XMMR1_XMMR2                            0x00C0590F           
#define X86IM_GEN_CODE_MULPS_XMMRG_MM                               0x0000590F    

#define X86IM_GEN_MULPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_MULPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MULPS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_MULPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MULSS_XMMR1_XMMR2                            0x00C0590F           
#define X86IM_GEN_CODE_MULSS_XMMRG_MM                               0x0000590F    

#define X86IM_GEN_MULSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MULSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MULSS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MULSS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ORPS_XMMR1_XMMR2                             0x0000560F        
#define X86IM_GEN_CODE_ORPS_XMMRG_MM                                0x0000560F         

#define X86IM_GEN_ORPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )          x86im_gen( io, mode, X86IM_GEN_CODE_ORPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ORPS_XMMRG_MM( io, mode, xmrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_ORPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_RCPPS_XMMR1_XMMR2                                    0x0000530F    
#define X86IM_GEN_CODE_RCPPS_XMMRG_MM                                       0x0000530F    

#define X86IM_GEN_RCPPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )                 x86im_gen( io, mode, X86IM_GEN_CODE_RCPPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_RCPPS_XMMRG_MM( io, mode, xmrg, mm )                      x86im_gen( io, mode, X86IM_GEN_CODE_RCPPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_RCPSS_XMMR1_XMMR2                                    0x00C0530F                 
#define X86IM_GEN_CODE_RCPSS_XMMRG_MM32                                     0x0000530F   

#define X86IM_GEN_RCPSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )                 x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_RCPSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_RCPSS_XMMRG_MM32( io, mode, xmrg, mm )                    x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_RCPSS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_RSQRTPS_XMMR1_XMMR2                                  0x00C0520F     
#define X86IM_GEN_CODE_RSQRTPS_XMMRG_MM                                     0x0000520F   

#define X86IM_GEN_RSQRTPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )               x86im_gen( io, mode, X86IM_GEN_CODE_RSQRTPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_RSQRTPS_XMMRG_MM( io, mode, xmrg, mm )                    x86im_gen( io, mode, X86IM_GEN_CODE_RSQRTPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 ) 

#define X86IM_GEN_CODE_RSQRTSS_XMMR1_XMMR2                                  0x0000520F           
#define X86IM_GEN_CODE_RSQRTSS_XMMRG_MM32                                   0x0000520F    

#define X86IM_GEN_RSQRTSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )               x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_RSQRTSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )      
#define X86IM_GEN_RSQRTSS_XMMRG_MM32( io, mode, xmrg, mm )                  x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_RSQRTSS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 ) 

#define X86IM_GEN_CODE_SHUFPS_XMMR1_XMMR2_IMM8                              0x00C0C60F    
#define X86IM_GEN_CODE_SHUFPS_XMMRG_MM_IMM8                                 0x0000C60F    

#define X86IM_GEN_SHUFPS_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )     x86im_gen( io, mode, X86IM_GEN_CODE_SHUFPS_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_SHUFPS_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )          x86im_gen( io, mode, X86IM_GEN_CODE_SHUFPS_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_SQRTPS_XMMR1_XMMR2                           0x00C0510F                
#define X86IM_GEN_CODE_SQRTPS_XMMRG_MM                              0x0000510F    

#define X86IM_GEN_SQRTPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_SQRTPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_SQRTPS_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode, X86IM_GEN_CODE_SQRTPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SQRTSS_XMMR1_XMMR2                           0x00C0510F                 
#define X86IM_GEN_CODE_SQRTSS_XMMRG_MM32                            0x0000510F    

#define X86IM_GEN_SQRTSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_SQRTSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )               
#define X86IM_GEN_SQRTSS_XMMRG_MM32( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_SQRTSS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SUBPS_XMMR1_XMMR2                            0x00C05C0F        
#define X86IM_GEN_CODE_SUBPS_XMMRG_MM                               0x00005C0F   

#define X86IM_GEN_SUBPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_SUBPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_SUBPS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_SUBPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SUBSS_XMMR1_XMMR2                            0x00C05C0F               
#define X86IM_GEN_CODE_SUBSS_XMMRG_MM32                             0x00005C0F    

#define X86IM_GEN_SUBSS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_SUBSS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_SUBSS_XMMRG_MM32( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_SUBSS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_UCOMISS_XMMR1_XMMR2                          0x00C02E0F          
#define X86IM_GEN_CODE_UCOMISS_XMMRG_MM32                           0x00002E0F    

#define X86IM_GEN_UCOMISS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode, X86IM_GEN_CODE_UCOMISS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_UCOMISS_XMMRG_MM32( io, mode, xmrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_UCOMISS_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_UNPCKHPS_XMMR1_XMMR2                         0x00C0150F    
#define X86IM_GEN_CODE_UNPCKHPS_XMMRG_MM                            0x0000150F    

#define X86IM_GEN_UNPCKHPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_UNPCKHPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_UNPCKHPS_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_UNPCKHPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 ) 

#define X86IM_GEN_CODE_UNPCKLPS_XMMR1_XMMR2                         0x00C0140F          
#define X86IM_GEN_CODE_UNPCKLPS_XMMRG_MM                            0x0000140F    

#define X86IM_GEN_UNPCKLPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_UNPCKLPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_UNPCKLPS_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_UNPCKLPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_XORPS_XMMR1_XMMR2                            0x00C0570F   
#define X86IM_GEN_CODE_XORPS_XMMRG_MM                               0x0000570F   

#define X86IM_GEN_XORPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_XORPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_XORPS_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_XORPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PEXTRW_R1_MMXR2_IMM8                             0x0000C50F            
#define X86IM_GEN_CODE_PMOVMSKB_R1_MMXR2                                0x0000D70F           

#define X86IM_GEN_PEXTRW_R1_MMXR2_IMM8( io, mode, r1, mxr2, imm8 )      x86im_gen( io, mode, X86IM_GEN_CODE_PEXTRW_R1_MMXR2_IMM8, X86IM_GEN_R1_MXR2( r1, mxr2 ), 0, 0, imm8 )
#define X86IM_GEN_PMOVMSKB_R1_MMXR2( io, mode, r1, mxr2 )               x86im_gen( io, mode, X86IM_GEN_CODE_PMOVMSKB_R1_MMXR2, X86IM_GEN_R1_MXR2( r1, mxr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_PAVGB_MMXR1_MMXR2                                0x00C0E00F    
#define X86IM_GEN_CODE_PAVGB_MMXRG_MM64                                 0x0000E00F    

#define X86IM_GEN_PAVGB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )             x86im_gen( io, mode, X86IM_GEN_CODE_PAVGB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PAVGB_MMXRG_MM64( io, mode, mxrg, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_PAVGB_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PAVGW_MMXR1_MMXR2                                0x00C0E30F    
#define X86IM_GEN_CODE_PAVGW_MMXRG_MM64                                 0x0000E30F    

#define X86IM_GEN_PAVGW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )             x86im_gen( io, mode, X86IM_GEN_CODE_PAVGW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PAVGW_MMXRG_MM64( io, mode, mxrg, mm )                x86im_gen( io, mode, X86IM_GEN_CODE_PAVGW_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PINSRW_MMXR1_R2_IMM8                             0x00C0C40F             
#define X86IM_GEN_CODE_PINSRW_MMXRG_MM16_IMM8                           0x0000C40F    

#define X86IM_GEN_PINSRW_MMXR1_R2_IMM8( io, mode, mxr1, r2, imm8 )      x86im_gen( io, mode, X86IM_GEN_CODE_PINSRW_MMXR1_R2_IMM8, X86IM_GEN_MXR1_R2( mxr1, r2 ), 0, 0, imm8 )    
#define X86IM_GEN_PINSRW_MMXRG_MM16_IMM8( io, mode, mxrg, mm, imm8 )    x86im_gen( io, mode, X86IM_GEN_CODE_PINSRW_MMXRG_MM16_IMM8, X86IM_GEN_MXRG_MM( mxrg ), mm, imm8 )

#define X86IM_GEN_CODE_PMAXSW_MMXR1_MMXR2                               0x00C0EE0F    
#define X86IM_GEN_CODE_PMAXSW_MMXRG_MM64                                0x0000EE0F    

#define X86IM_GEN_PMAXSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )            x86im_gen( io, mode, X86IM_GEN_CODE_PMAXSW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMAXSW_MMXRG_MM64( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_PMAXSW_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PMAXUB_MMXR1_MMXR2                               0x00C0DE0F  
#define X86IM_GEN_CODE_PMAXUB_MMXRG_MM64                                0x0000DE0F  

#define X86IM_GEN_PMAXUB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )            x86im_gen( io, mode, X86IM_GEN_CODE_PMAXUB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )              
#define X86IM_GEN_PMAXUB_MMXRG_MM64( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_PMAXUB_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 ) 

#define X86IM_GEN_CODE_PMINSW_MMXR1_MMXR2                               0x00C0EA0F      
#define X86IM_GEN_CODE_PMINSW_MMXRG_MM64                                0x0000EA0F    

#define X86IM_GEN_PMINSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )            x86im_gen( io, mode, X86IM_GEN_CODE_PMINSW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )              
#define X86IM_GEN_PMINSW_MMXRG_MM64( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_PMINSW_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 ) 

#define X86IM_GEN_CODE_PMINUB_MMXR1_MMXR2                               0x0000DA0F      
#define X86IM_GEN_CODE_PMINUB_MMXRG_MM64                                0x0000DA0F    

#define X86IM_GEN_PMINUB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )            x86im_gen( io, mode, X86IM_GEN_CODE_PMINUB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )              
#define X86IM_GEN_PMINUB_MMXRG_MM64( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_PMINUB_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 ) 

#define X86IM_GEN_CODE_PMULHUW_MMXR1_MMXR2                              0x0000E40F          
#define X86IM_GEN_CODE_PMULHUW_MMXRG_MM64                               0x0000E40F    

#define X86IM_GEN_PMULHUW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )           x86im_gen( io, mode, X86IM_GEN_CODE_PMULHUW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULHUW_MMXRG_MM64( io, mode, mxrg, mm )              x86im_gen( io, mode, X86IM_GEN_CODE_PMULHUW_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 ) 

#define X86IM_GEN_CODE_PSADBW_MMXR1_MMXR2                               0x0000F60F         
#define X86IM_GEN_CODE_PSADBW_MMXRG_MM64                                0x0000F60F    

#define X86IM_GEN_PSADBW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )            x86im_gen( io, mode, X86IM_GEN_CODE_PSADBW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )              
#define X86IM_GEN_PSADBW_MMXRG_MM64( io, mode, mxrg, mm )               x86im_gen( io, mode, X86IM_GEN_CODE_PSADBW_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_PSHUFW_MMXR1_MMXR2_IMM8                              0x0000700F           
#define X86IM_GEN_CODE_PSHUFW_MMXRG_MM64_IMM8                               0x0000700F    

#define X86IM_GEN_PSHUFW_MMXR1_MMXR2_IMM8( io, mode, mxr1, mxr2, imm8 )     x86im_gen( io, mode, X86IM_GEN_CODE_PSHUFW_MMXR1_MMXR2_IMM8, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, imm8 )     
#define X86IM_GEN_PSHUFW_MMXRG_MM64_IMM8( io, mode, mxrg, mm, imm8 )        x86im_gen( io, mode, X86IM_GEN_CODE_PSHUFW_MMXRG_MM64_IMM8, X86IM_GEN_MXRG_MM( mxrg ), mm, imm8 )

// SSE2                                 

#define X86IM_GEN_CODE_MOVMSKPD_R1_XMMR2                            0x0000500F           
#define X86IM_GEN_MOVMSKPD_R1_XMMR2( io, mode, r1, xmr2 )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVMSKPD_R1_XMMR2, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_MASKMOVDQU_XMMR1_XMMR2                       0x0000F70F        
#define X86IM_GEN_MASKMOVDQU_XMMR1_XMMR2( io, mode, xmr1, xmr2 )    x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MASKMOVDQU_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )          

#define X86IM_GEN_CODE_CLFLUSH_MM8                                  0x0038AE0F                  
#define X86IM_GEN_CLFLUSH_MM8( io, mode, mm )                       x86im_gen( io, mode, X86IM_GEN_CODE_CLFLUSH_MM8, 0, mm, 0 ) 

#define X86IM_GEN_CODE_MOVNTPD_MM_XMMRG                             0x00002B0F    
#define X86IM_GEN_MOVNTPD_MM_XMMRG( io, mode, mm, xmrg )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVNTPD_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )  

#define X86IM_GEN_CODE_MOVNTDQ_MM_XMMRG                             0x0000E70F                  
#define X86IM_GEN_MOVNTDQ_MM_XMMRG( io, mode, mm, xmrg )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVNTDQ_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVNTI_MM_RG                                 0x0000C30F                   
#define X86IM_GEN_MOVNTI_MM_RG( io, mode, mm, rg )                  x86im_gen( io, mode, X86IM_GEN_CODE_MOVNTI_MM_RG, X86IM_GEN_MM_RG( rg ), mm, 0 )

#define X86IM_GEN_CODE_PAUSE                                        0x00000090
#define X86IM_GEN_PAUSE( io, mode )                                 x86im_gen( io, mode, X86IM_GEN_CODE_PAUSE, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_LFENCE                                       0x00E8AE0F                       
#define X86IM_GEN_LFENCE( io, mode )                                x86im_gen( io, mode, X86IM_GEN_CODE_LFENCE, 0, 0, 0, 0 )         

#define X86IM_GEN_CODE_MFENCE                                       0x00F0AE0F                        
#define X86IM_GEN_MFENCE( io, mode )                                x86im_gen( io, mode, X86IM_GEN_CODE_MFENCE, 0, 0, 0, 0 ) 

#define X86IM_GEN_CODE_ADDPD_XMMR1_XMMR2                            0x00C0580F    
#define X86IM_GEN_CODE_ADDPD_XMMRG_MM                               0x0000580F    

#define X86IM_GEN_ADDPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ADDPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ADDPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ADDPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ADDSD_XMMR1_XMMR2                            0x00C0580F                 
#define X86IM_GEN_CODE_ADDSD_XMMRG_MM64                             0x0000580F       

#define X86IM_GEN_ADDSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_ADDSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ADDSD_XMMRG_MM64( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_ADDSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ANDNPD_XMMR1_XMMR2                           0x00C0550F    
#define X86IM_GEN_CODE_ANDNPD_XMMRG_MM                              0x0000550F          

#define X86IM_GEN_ANDNPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ANDNPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )   
#define X86IM_GEN_ANDNPD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ANDNPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ANDPD_XMMR1_XMMR2                            0x00C0540F                 
#define X86IM_GEN_CODE_ANDPD_XMMRG_MM                               0x0000540F        

#define X86IM_GEN_ANDPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ANDPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ANDPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ANDPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CMPPD_XMMR1_XMMR2_IMM8                           0x00C0C20F       
#define X86IM_GEN_CODE_CMPPD_XMMRG_MM_IMM8                              0x0000C20F      

#define X86IM_GEN_CMPPD_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )  x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CMPPD_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_CMPPD_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CMPPD_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_CMPSD_XMMR1_XMMR2_IMM8                               0x00C0C20F         
#define X86IM_GEN_CODE_CMPSD_XMMRG_MM64_IMM8                                0x0000C20F    

#define X86IM_GEN_CMPSD_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )      x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CMPSD_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_CMPSD_XMMRG_MM64_IMM8( io, mode, xmrg, mm, imm8 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CMPSD_XMMRG_MM64_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_COMISD_XMMR1_XMMR2                           0x00C02E0F               
#define X86IM_GEN_CODE_COMISD_XMMRG_MM64                            0x00002E0F       

#define X86IM_GEN_COMISD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_COMISD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_COMISD_XMMRG_MM64( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_COMISD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTPI2PD_XMMR1_MMXR2                         0x00C02A0F             
#define X86IM_GEN_CODE_CVTPI2PD_XMMRG_MM64                          0x00002A0F     

#define X86IM_GEN_CVTPI2PD_XMMR1_MMXR2( io, mode, xmr1, mmxr2 )     x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPI2PD_XMMR1_MMXR2, X86IM_GEN_XMR1_MXR2( xmr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTPI2PD_XMMRG_MM64( io, mode, xmrg, mm )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPI2PD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTPD2PI_MMXR1_XMMR2                         0x00C02D0F            
#define X86IM_GEN_CODE_CVTPD2PI_MMXRG_MM                            0x00002D0F         

#define X86IM_GEN_CVTPD2PI_MMXR1_XMMR2( io, mode, mxr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPD2PI_MMXR1_XMMR2, X86IM_GEN_MXR1_XMR2( mxr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTPD2PI_MMXRG_MM( io, mode, mxrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPD2PI_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTSI2SD_XMMR1_R2                            0x00C02A0F               
#define X86IM_GEN_CODE_CVTSI2SD_XMMRG_MM                            0x00002A0F          

#define X86IM_GEN_CVTSI2SD_XMMR1_R2( io, mode, xmr1, r2 )           x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTSI2SD_XMMR1_R2, X86IM_GEN_XMR1_R2( xmr1, r2 ), 0, 0, 0 )
#define X86IM_GEN_CVTSI2SD_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTSI2SD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTSD2SI_R1_XMMR2                            0x00C02D0F             
#define X86IM_GEN_CODE_CVTSD2SI_RG_MM64                             0x00002D0F           

#define X86IM_GEN_CVTSD2SI_R1_XMMR2( io, mode, r1, xmr2 )           x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTSD2SI_R1_XMMR2, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTSD2SI_RG_MM64( io, mode, rg, mm )              x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTSD2SI_RG_MM64, X86IM_GEN_RG_MM( rg  ), mm, 0 )

#define X86IM_GEN_CODE_CVTTPD2PI_MMXR1_XMMR2                        0x00C02C0F             
#define X86IM_GEN_CODE_CVTTPD2PI_MMXRG_MM                           0x00002C0F        

#define X86IM_GEN_CVTTPD2PI_MMXR1_XMMR2( io, mode, mxr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTTPD2PI_MMXR1_XMMR2, X86IM_GEN_MXR1_XMR2( mxr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTTPD2PI_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTTPD2PI_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTTSD2SI_R1_XMMR2                           0x00C02C0F                
#define X86IM_GEN_CODE_CVTTSD2SI_RG_MM64                            0x00002C0F            

#define X86IM_GEN_CVTTSD2SI_R1_XMMR2( io, mode, r1, xmr2 )          x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTTSD2SI_R1_XMMR2, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTTSD2SI_RG_MM64( io, mode, rg, mm )             x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTTSD2SI_RG_MM64, X86IM_GEN_RG_MM( rg ), mm, 0 )

#define X86IM_GEN_CODE_CVTPD2PS_XMMR1_XMMR2                         0x00C05A0F        
#define X86IM_GEN_CODE_CVTPD2PS_XMMRG_MM                            0x00005A0F    

#define X86IM_GEN_CVTPD2PS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPD2PS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTPD2PS_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPD2PS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
 
#define X86IM_GEN_CODE_CVTPS2PD_XMMR1_XMMR2                         0x00C05A0F             
#define X86IM_GEN_CODE_CVTPS2PD_XMMRG_MM64                          0x00005A0F        

#define X86IM_GEN_CVTPS2PD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_CVTPS2PD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTPS2PD_XMMRG_MM64( io, mode, xmrg, mm )         x86im_gen( io, mode, X86IM_GEN_CODE_CVTPS2PD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTSD2SS_XMMR1_XMMR2                         0x00C05A0F       
#define X86IM_GEN_CODE_CVTSD2SS_XMMRG_MM64                          0x00005A0F         

#define X86IM_GEN_CVTSD2SS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTSD2SS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_CVTSD2SS_XMMRG_MM64( io, mode, xmrg, mm )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTSD2SS_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTSS2SD_XMMR1_XMMR2                         0x00C05A0F           
#define X86IM_GEN_CODE_CVTSS2SD_XMMRG_MM32                          0x00005A0F        

#define X86IM_GEN_CVTSS2SD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTSS2SD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_CVTSS2SD_XMMRG_MM32( io, mode, xmrg, mm )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTSS2SD_XMMRG_MM32, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTPD2DQ_XMMR1_XMMR2                         0x00C0E60F     
#define X86IM_GEN_CODE_CVTPD2DQ_XMMRG_MM                            0x0000E60F          

#define X86IM_GENCVTPD2DQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTPD2DQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GENCVTPD2DQ_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_CVTPD2DQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTTPD2DQ_XMMR1_XMMR2                        0x00C0E60F        
#define X86IM_GEN_CODE_CVTTPD2DQ_XMMRG_MM                           0x0000E60F   

#define X86IM_GEN_CVTTPD2DQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_CVTTPD2DQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )  
#define X86IM_GEN_CVTTPD2DQ_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_CVTTPD2DQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTDQ2PD_XMMR1_XMMR2                         0x00C0E60F             
#define X86IM_GEN_CODE_CVTDQ2PD_XMMRG_MM64                          0x0000E60F        

#define X86IM_GEN_CVTDQ2PD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTDQ2PD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTDQ2PD_XMMRG_MM64( io, mode, xmrg, mm )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTDQ2PD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTPS2DQ_XMMR1_XMMR2                         0x00C05B0F        
#define X86IM_GEN_CODE_CVTPS2DQ_XMMRG_MM                            0x00005B0F         

#define X86IM_GEN_CVTPS2DQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPS2DQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTPS2DQ_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_CVTPS2DQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTTPS2DQ_XMMR1_XMMR2                        0x00C05B0F          
#define X86IM_GEN_CODE_CVTTPS2DQ_XMMRG_MM                           0x00005B0F    

#define X86IM_GEN_CVTTPS2DQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTTPS2DQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTTPS2DQ_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_CVTTPS2DQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_CVTDQ2PS_XMMR1_XMMR2                         0x00C05B0F             
#define X86IM_GEN_CODE_CVTDQ2PS_XMMRG_MM                            0x00005B0F       

#define X86IM_GEN_CVTDQ2PS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_CVTDQ2PS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_CVTDQ2PS_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_CVTDQ2PS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_DIVPD_XMMR1_XMMR2                            0x00C05E0F              
#define X86IM_GEN_CODE_DIVPD_XMMRG_MM                               0x00005E0F        

#define X86IM_GEN_DIVPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_DIVPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_DIVPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_DIVPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_DIVSD_XMMR1_XMMR2                            0x00C05E0F            
#define X86IM_GEN_CODE_DIVSD_XMMRG_MM64                             0x00005E0F             

#define X86IM_GEN_DIVSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_DIVSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_DIVSD_XMMRG_MM64( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_DIVSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MAXPD_XMMR1_XMMR2                            0x00C05F0F               
#define X86IM_GEN_CODE_MAXPD_XMMRG_MM                               0x00005F0F            

#define X86IM_GEN_MAXPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MAXPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MAXPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MAXPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MAXSD_XMMR1_XMMR2                            0x00C05F0F             
#define X86IM_GEN_CODE_MAXSD_XMMRG_MM64                             0x00005F0F        

#define X86IM_GEN_MAXSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MAXSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MAXSD_XMMRG_MM64( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MAXSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MINPD_XMMR1_XMMR2                            0x00C05D0F                 
#define X86IM_GEN_CODE_MINPD_XMMRG_MM                               0x00005D0F            

#define X86IM_GEN_MINPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MINPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_MINPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MINPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MINSD_XMMR1_XMMR2                            0x00C05D0F            
#define X86IM_GEN_CODE_MINSD_XMMRG_MM64                             0x00005D0F        

#define X86IM_GEN_MINSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MINSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MINSD_XMMRG_MM64( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MINSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVAPD_XMMR1_XMMR2                           0x00C0280F         
#define X86IM_GEN_CODE_MOVAPD_XMMRG_MM                              0x0000280F    
#define X86IM_GEN_CODE_MOVAPD_XMMR2_XMMR1                           0x00C0290F          
#define X86IM_GEN_CODE_MOVAPD_MM_XMMRG                              0x0000290F     

#define X86IM_GEN_MOVAPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVAPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_MOVAPD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVAPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVAPD_XMMR2_XMMR1( io, mode, xmr2, xmr1 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVAPD_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVAPD_MM_XMMRG( io, mode, mm, xmrg )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVAPD_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVHPD_XMMRG_MM64                            0x0000160F              
#define X86IM_GEN_CODE_MOVHPD_MM64_XMMRG                            0x0000170F              

#define X86IM_GEN_MOVHPD_XMMRG_MM64( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVHPD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVHPD_MM64_XMMRG( io, mode, mm, xmrg )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVHPD_MM64_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVLPD_XMMRG_MM64                            0x0000120F              
#define X86IM_GEN_CODE_MOVLPD_MM64_XMMRG                            0x0000130F            

#define X86IM_GEN_MOVLPD_XMMRG_MM64( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVLPD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 ) 
#define X86IM_GEN_MOVLPD_MM64_XMMRG( io, mode, mm, xmrg )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVLPD_MM64_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVSD_XMMR1_XMMR2                            0x00C0100F                 
#define X86IM_GEN_CODE_MOVSD_XMMRG_MM64                             0x0000100F    
#define X86IM_GEN_CODE_MOVSD_XMMR2_XMMR1                            0x00C0110F              
#define X86IM_GEN_CODE_MOVSD_MM64_XMMRG                             0x0000110F         

#define X86IM_GEN_MOVSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MOVSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSD_XMMRG_MM64( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MOVSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVSD_XMMR2_XMMR1( io, mode, xmr2, xmr1 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MOVSD_XMMR2_XMMR1,  X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVSD_MM64_XMMRG( io, mode, mm, xmrg )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MOVSD_MM64_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVUPD_XMMR1_XMMR2                           0x00C0100F  
#define X86IM_GEN_CODE_MOVUPD_XMMRG_MM                              0x0000100F
#define X86IM_GEN_CODE_MOVUPD_XMMR2_XMMR1                           0x00C0110F  
#define X86IM_GEN_CODE_MOVUPD_MM_XMMRG                              0x0000110F

#define X86IM_GEN_MOVUPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVUPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVUPD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVUPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVUPD_XMMR2_XMMR1( io, mode, xmr2, xmr1 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVUPD_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVUPD_MM_XMMRG( io, mode, mm, xmrg )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVUPD_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MULPD_XMMR1_XMMR2                            0x00C0590F                 
#define X86IM_GEN_CODE_MULPD_XMMRG_MM                               0x0000590F

#define X86IM_GEN_MULPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MULPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MULPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MULPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MULSD_XMMR1_XMMR2                            0x00C0590F    
#define X86IM_GEN_CODE_MULSD_XMMRG_MM64                             0x0000590F

#define X86IM_GEN_MULSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MULSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MULSD_XMMRG_MM64( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MULSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ORPD_XMMR1_XMMR2                             0x00C0560F                 
#define X86IM_GEN_CODE_ORPD_XMMRG_MM                                0x0000560F            

#define X86IM_GEN_ORPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ORPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ORPD_XMMRG_MM( io, mode, xmrg, mm )               x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ORPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SHUFPD_XMMR1_XMMR2_IMM8                              0x00C0C60F 
#define X86IM_GEN_CODE_SHUFPD_XMMRG_MM_IMM8                                 0x0000C60F    

#define X86IM_GEN_SHUFPD_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )     x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_SHUFPD_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_SHUFPD_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_SHUFPD_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SQRTPD_XMMR1_XMMR2                           0x00C0510F               
#define X86IM_GEN_CODE_SQRTPD_XMMRG_MM                              0x0000510F

#define X86IM_GEN_SQRTPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_SQRTPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_SQRTPD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_SQRTPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SQRTSD_XMMR1_XMMR2                           0x00C0510F                
#define X86IM_GEN_CODE_SQRTSD_XMMRG_MM64                            0x0000510F         

#define X86IM_GEN_SQRTSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_SQRTSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_SQRTSD_XMMRG_MM64( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_SQRTSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SUBPD_XMMR1_XMMR2                            0x00C05C0F          
#define X86IM_GEN_CODE_SUBPD_XMMRG_MM                               0x00005C0F

#define X86IM_GEN_SUBPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_SUBPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_SUBPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_SUBPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_SUBSD_XMMR1_XMMR2                            0x00C05C0F                
#define X86IM_GEN_CODE_SUBSD_XMMRG_MM64                             0x00005C0F

#define X86IM_GEN_SUBSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_SUBSD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_SUBSD_XMMRG_MM64( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_SUBSD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_UCOMISD_XMMR1_XMMR2                          0x00C02E0F           
#define X86IM_GEN_CODE_UCOMISD_XMMRG_MM64                           0x00002E0F

#define X86IM_GEN_UCOMISD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_UCOMISD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_UCOMISD_XMMRG_MM64( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_UCOMISD_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_UNPCKHPD_XMMR1_XMMR2                         0x00C0150F            
#define X86IM_GEN_CODE_UNPCKHPD_XMMRG_MM                            0x0000150F

#define X86IM_GEN_UNPCKHPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_UNPCKHPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_UNPCKHPD_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_UNPCKHPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_UNPCKLPD_XMMR1_XMMR2                         0x00C0140F             
#define X86IM_GEN_CODE_UNPCKLPD_XMMRG_MM                            0x0000140F

#define X86IM_GEN_UNPCKLPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_UNPCKLPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_UNPCKLPD_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_UNPCKLPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_XORPD_XMMR1_XMMR2                            0x00C0570F              
#define X86IM_GEN_CODE_XORPD_XMMRG_MM                               0x0000570F

#define X86IM_GEN_XORPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_XORPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_XORPD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_XORPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVQ2DQ_XMMR1_MMXR2                          0x0000D60F        
#define X86IM_GEN_MOVQ2DQ_XMMR1_MMXR2( io, mode, xmr1, mxr2 )       x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVQ2DQ_XMMR1_MMXR2, X86IM_GEN_XMR1_MXR2( xmr1, mxr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_MOVDQ2Q_MMXR1_XMMR2                          0x0000D60F    
#define X86IM_GEN_MOVDQ2Q_MMXR1_XMMR2( io, mode, mxr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MOVDQ2Q_MMXR1_XMMR2, X86IM_GEN_MXR1_XMR2( mxr1, xmr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_PEXTRW_R1_XMMR2_IMM8                         0x0000C50F   
#define X86IM_GEN_PEXTRW_R1_XMMR2_IMM8( io, mode, r1, xmr2, imm8 )  x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PEXTRW_R1_XMMR2_IMM8, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, imm8 )

#define X86IM_GEN_CODE_PMOVMSKB_R1_XMMR2                            0x0000D70F                
#define X86IM_GEN_PMOVMSKB_R1_XMMR2( io, mode, r1, xmr2 )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMOVMSKB_R1_XMMR2, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )

#define X86IM_GEN_CODE_PSLLDQ_XMMRG_IMM8                            0x00F8730F                
#define X86IM_GEN_PSLLDQ_XMMRG_IMM8( io, mode, xmrg, imm8 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLDQ_XMMRG_IMM8, xmrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRLDQ_XMMRG_IMM8                            0x00D8730F    
#define X86IM_GEN_PSRLDQ_XMMRG_IMM8( io, mode, xmrg, imm8 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLDQ_XMMRG_IMM8, xmrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_MOVD_XMMRG_RG                                0x00C06E0F   
#define X86IM_GEN_CODE_MOVD_XMMRG_MM                                0x00006E0F
#define X86IM_GEN_CODE_MOVD_RG_XMMRG                                0x00C07E0F                
#define X86IM_GEN_CODE_MOVD_MM_XMMRG                                0x00007E0F

#define X86IM_GEN_MOVD_XMMR1_R2( io, mode, xmr1, r2 )               x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVD_XMMRG_RG, X86IM_GEN_XMR1_R2( xmr1, r2 ), 0, 0, 0 )
#define X86IM_GEN_MOVD_XMMRG_MM( io, mode, xmrg, mm )               x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVD_R2_XMMR1( io, mode, r1, xmr2 )               x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVD_RG_XMMRG, X86IM_GEN_R1_XMR2( r1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVD_MM_XMMRG( io, mode, mm, xmrg )               x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVD_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVDQA_XMMR1_XMMR2                           0x00C06F0F               
#define X86IM_GEN_CODE_MOVDQA_XMMRG_MM                              0x00006F0F    
#define X86IM_GEN_CODE_MOVDQA_XMMR2_XMMR1                           0x00C07F0F              
#define X86IM_GEN_CODE_MOVDQA_MM_XMMRG                              0x00007F0F

#define X86IM_GEN_MOVDQA_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVDQA_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVDQA_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVDQA_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVDQA_XMMR2_XMMR1( io, mode, xmr2, xmr1 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVDQA_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVDQA_MM_XMMRG( io, mode, mm, xmrg )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVDQA_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVDQU_XMMR1_XMMR2                           0x00C06F0F              
#define X86IM_GEN_CODE_MOVDQU_XMMRG_MM                              0x00006F0F            
#define X86IM_GEN_CODE_MOVDQU_XMMR2_XMMR1                           0x00C07F0F    
#define X86IM_GEN_CODE_MOVDQU_MM_XMMRG                              0x00007F0F            

#define X86IM_GEN_MOVDQU_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVDQU_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVDQU_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVDQU_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVDQU_XMMR2_XMMR1( io, mode, xmr2, xmr1 )        x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVDQU_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVDQU_MM_XMMRG( io, mode, mm, xmrg )             x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVDQU_MM_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVQ_XMMR1_XMMR2                             0x00C07E0F                   
#define X86IM_GEN_CODE_MOVQ_XMMRG_MM64                              0x00007E0F    
#define X86IM_GEN_CODE_MOVQ_XMMR2_XMMR1                             0x00C0D60F               
#define X86IM_GEN_CODE_MOVQ_MM64_XMMRG                              0x0000D60F        

#define X86IM_GEN_MOVQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )          x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVQ_XMMRG_MM64( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVQ_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_MOVQ_XMMR2_XMMR1( io, mode, xmr2, xmr1 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVQ_XMMR2_XMMR1, X86IM_GEN_XMR2_XMR1( xmr2, xmr1 ), 0, 0, 0 )
#define X86IM_GEN_MOVQ_MM64_XMMRG( io, mode, mm, xmrg )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_MOVQ_MM64_XMMRG, X86IM_GEN_MM_XMRG( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PACKSSDW_XMMR1_XMMR2                         0x00C06B0F             
#define X86IM_GEN_CODE_PACKSSDW_XMMRG_MM                            0x00006B0F        

#define X86IM_GEN_PACKSSDW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PACKSSDW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PACKSSDW_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PACKSSDW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PACKSSWB_XMMR1_XMMR2                         0x00C0630F            
#define X86IM_GEN_CODE_PACKSSWB_XMMRG_MM                            0x0000630F        

#define X86IM_GEN_PACKSSWB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PACKSSWB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PACKSSWB_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PACKSSWB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PACKUSWB_XMMR1_XMMR2                         0x00C0670F    
#define X86IM_GEN_CODE_PACKUSWB_XMMRG_MM                            0x0000670F 

#define X86IM_GEN_PACKUSWB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PACKUSWB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PACKUSWB_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PACKUSWB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PADDQ_MMXR1_MMXR2                            0x00C0D40F                
#define X86IM_GEN_CODE_PADDQ_MMXRG_MM64                             0x0000D40F        
#define X86IM_GEN_CODE_PADDQ_XMMR1_XMMR2                            0x00C0D40F           
#define X86IM_GEN_CODE_PADDQ_XMMRG_MM                               0x0000D40F

#define X86IM_GEN_PADDQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PADDQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDQ_MMXRG_MM64( io, mode, mxrg, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_PADDQ_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PADDQ_XMMR1_XMMR2( io, mode, mxr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PADDQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDQ_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PADDQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PADDX_XMMR1_XMMR2                            0x00C0FC0F   
#define X86IM_GEN_CODE_PADDX_XMMRG_MM                               0x0000FC0F         
    
#define X86IM_GEN_PADDB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDB_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PADDW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDW_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PADDD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PADDX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PADDX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PADDSX_XMMR1_XMMR2                           0x00C0EC0F    
#define X86IM_GEN_CODE_PADDSX_XMMRG_MM                              0x0000EC0F

#define X86IM_GEN_PADDSB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDSB_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PADDSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDSW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PADDUSX_XMMR1_XMMR2                          0x00C0DC0F    
#define X86IM_GEN_CODE_PADDUSX_XMMRG_MM                             0x0000DC0F

#define X86IM_GEN_PADDUSB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDUSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDUSB_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PADDUSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PADDUSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDUSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PADDUSW_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PADDUSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PAND_XMMR1_XMMR2                             0x00C0DB0F                
#define X86IM_GEN_CODE_PAND_XMMRG_MM                                0x0000DB0F            

#define X86IM_GEN_PAND_XMMR1_XMMR2( io, mode, xmr1, xmr2 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PAND_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PAND_XMMRG_MM( io, mode, xmrg, mm )               x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PAND_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PANDN_XMMR1_XMMR2                            0x00C0DF0F                 
#define X86IM_GEN_CODE_PANDN_XMMRG_MM                               0x0000DF0F

#define X86IM_GEN_PANDN_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PANDN_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PANDN_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PANDN_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PAVGB_XMMR1_XMMR2                            0x00C0E00F    
#define X86IM_GEN_CODE_PAVGB_XMMRG_MM                               0x0000E00F

#define X86IM_GEN_PAVGB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PAVGB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PAVGB_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PAVGB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PAVGW_XMMR1_XMMR2                            0x00C0E30F           
#define X86IM_GEN_CODE_PAVGW_XMMRG_MM                               0x0000E30F

#define X86IM_GEN_PAVGW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PAVGW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PAVGW_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PAVGW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PCMPEQX_XMMR1_XMMR2                          0x00C0740F             
#define X86IM_GEN_CODE_PCMPEQX_XMMRG_MM                             0x0000740F

#define X86IM_GEN_PCMPEQB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPEQX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPEQB_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPEQX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PCMPEQW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPEQX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPEQW_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPEQX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PCMPEQD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPEQX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPEQD_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPEQX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PCMPGTX_XMMR1_XMMR2                          0x00C0640F   
#define X86IM_GEN_CODE_PCMPGTX_XMMRG_MM                             0x0000640F

#define X86IM_GEN_PCMPGTB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPGTX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPGTB_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PCMPGTX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PCMPGTW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPGTX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPGTW_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PCMPGTX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PCMPGTD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPGTX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PCMPGTD_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PCMPGTX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PINSRW_XMMR1_R2_IMM8                             0x00C0C40F             
#define X86IM_GEN_CODE_PINSRW_XMMRG_MM16_IMM8                           0x0000C40F

#define X86IM_GEN_PINSRW_XMMR1_R2_IMM8( io, mode, xmr1, r2, imm8 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PINSRW_XMMR1_R2_IMM8, X86IM_GEN_XMR1_R2( xmr1, r2 ), 0, 0, 0 )
#define X86IM_GEN_PINSRW_XMMRG_MM16_IMM8( io, mode, xmrg, mm, imm8 )    x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PINSRW_XMMRG_MM16_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMADDWD_XMMR1_XMMR2                          0x00C0F50F   
#define X86IM_GEN_CODE_PMADDWD_XMMRG_MM                             0x0000F50F 

#define X86IM_GEN_PMADDWD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMADDWD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMADDWD_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMADDWD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMAXSW_XMMR1_XMMR2                           0x00C0EE0F    
#define X86IM_GEN_CODE_PMAXSW_XMMRG_MM                              0x0000EE0F    

#define X86IM_GEN_PMAXSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMAXSW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMAXSW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMAXSW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMAXUB_XMMR1_XMMR2                           0x00C0DE0F               
#define X86IM_GEN_CODE_PMAXUB_XMMRG_MM                              0x0000DE0F

#define X86IM_GEN_PMAXUB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMAXUB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMAXUB_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMAXUB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMINSW_XMMR1_XMMR2                           0x00C0EA0F    
#define X86IM_GEN_CODE_PMINSW_XMMRG_MM                              0x0000EA0F     

#define X86IM_GEN_PMINSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMINSW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMINSW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMINSW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMINUB_XMMR1_XMMR2                           0x00C0DA0F   
#define X86IM_GEN_CODE_PMINUB_XMMRG_MM                              0x0000DA0F

#define X86IM_GEN_PMINUB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMINUB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMINUB_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMINUB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULHUW_XMMR1_XMMR2                          0x00C0E40F    
#define X86IM_GEN_CODE_PMULHUW_XMMRG_MM                             0x0000E40F

#define X86IM_GEN_PMULHUW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULHUW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULHUW_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULHUW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULHW_XMMR1_XMMR2                           0x00C0E50F               
#define X86IM_GEN_CODE_PMULHW_XMMRG_MM                              0x0000E50F

#define X86IM_GEN_PMULHW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULHW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULHW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULHW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULLW_XMMR1_XMMR2                           0x00C0D50F             
#define X86IM_GEN_CODE_PMULLW_XMMRG_MM                              0x0000D50F        

#define X86IM_GEN_PMULLW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULLW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULLW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULLW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULUDQ_MMXR1_MMXR2                          0x00C0F40F     
#define X86IM_GEN_CODE_PMULUDQ_MMXRG_MM64                           0x0000F40F
#define X86IM_GEN_CODE_PMULUDQ_XMMR1_XMMR2                          0x00C0F40F               
#define X86IM_GEN_CODE_PMULUDQ_XMMRG_MM                             0x0000F40F

#define X86IM_GEN_PMULUDQ_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULUDQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULUDQ_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULUDQ_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PMULUDQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULUDQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULUDQ_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULUDQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_POR_XMMR1_XMMR2                              0x00C0EB0F                  
#define X86IM_GEN_CODE_POR_XMMRG_MM                                 0x0000EB0F            

#define X86IM_GEN_POR_XMMR1_XMMR2( io, mode, xmr1, xmr2 )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_POR_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_POR_XMMRG_MM( io, mode, xmrg, mm )                x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_POR_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PSADBW_XMMR1_XMMR2                           0x00C0F60F    
#define X86IM_GEN_CODE_PSADBW_XMMRG_MM                              0x0000F60F           

#define X86IM_GEN_PSADBW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSADBW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSADBW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSADBW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PSHUFLW_XMMR1_XMMR2_IMM8                             0x00C0700F        
#define X86IM_GEN_CODE_PSHUFLW_XMMRG_MM_IMM8                                0x0000700F    

#define X86IM_GEN_PSHUFLW_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )    x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_PSHUFLW_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_PSHUFLW_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )         x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_PSHUFLW_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_PSHUFHW_XMMR1_XMMR2_IMM8                             0x00C0700F          
#define X86IM_GEN_CODE_PSHUFHW_XMMRG_MM_IMM8                                0x0000700F    

#define X86IM_GEN_PSHUFHW_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )    x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_PSHUFHW_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_PSHUFHW_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )         x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_PSHUFHW_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_PSHUFD_XMMR1_XMMR2_IMM8                              0x00C0700F          
#define X86IM_GEN_CODE_PSHUFD_XMMRG_MM_IMM8                                 0x0000700F

#define X86IM_GEN_PSHUFD_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )     x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSHUFD_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_PSHUFD_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSHUFD_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_PSLLW_XMMR1_XMMR2                            0x00C0F10F                  
#define X86IM_GEN_CODE_PSLLW_XMMRG_MM                               0x0000F10F    
#define X86IM_GEN_CODE_PSLLD_XMMR1_XMMR2                            0x00C0F20F                
#define X86IM_GEN_CODE_PSLLD_XMMRG_MM                               0x0000F20F
#define X86IM_GEN_CODE_PSLLQ_XMMR1_XMMR2                            0x00C0F30F                
#define X86IM_GEN_CODE_PSLLQ_XMMRG_MM                               0x0000F30F    
#define X86IM_GEN_CODE_PSLLW_XMMRG_IMM8                             0x0030710F               
#define X86IM_GEN_CODE_PSLLD_XMMRG_IMM8                             0x0030720F              
#define X86IM_GEN_CODE_PSLLQ_XMMRG_IMM8                             0x00F0730F             

#define X86IM_GEN_PSLLW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSLLW_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSLLD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSLLD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSLLQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSLLQ_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSLLW_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLW_XMMRG_IMM8, xmrg, 0, 0, imm8 )
#define X86IM_GEN_PSLLD_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLD_XMMRG_IMM8, xmrg, 0, 0, imm8 )
#define X86IM_GEN_PSLLQ_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSLLQ_XMMRG_IMM8, xmrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRAW_XMMR1_XMMR2                            0x00C0E10F                
#define X86IM_GEN_CODE_PSRAW_XMMRG_MM                               0x0000E10F
#define X86IM_GEN_CODE_PSRAD_XMMR1_XMMR2                            0x00C0E20F             
#define X86IM_GEN_CODE_PSRAD_XMMRG_MM                               0x0000E20F
#define X86IM_GEN_CODE_PSRAW_XMMRG_IMM8                             0x0020710F        
#define X86IM_GEN_CODE_PSRAD_XMMRG_IMM8                             0x0020720F    

#define X86IM_GEN_PSRAW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRAW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRAW_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRAW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSRAD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRAD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRAD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRAD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSRAW_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRAW_XMMRG_IMM8, xmrg, 0, 0, imm8 )
#define X86IM_GEN_PSRAD_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRAD_XMMRG_IMM8, xmrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSRLW_XMMR1_XMMR2                            0x00C0D10F       
#define X86IM_GEN_CODE_PSRLW_XMMRG_MM                               0x0000D10F 
#define X86IM_GEN_CODE_PSRLD_XMMR1_XMMR2                            0x00C0D20F         
#define X86IM_GEN_CODE_PSRLD_XMMRG_MM                               0x0000D20F 
#define X86IM_GEN_CODE_PSRLQ_XMMR1_XMMR2                            0x00C0D30F          
#define X86IM_GEN_CODE_PSRLQ_XMMRG_MM                               0x0000D30F
#define X86IM_GEN_CODE_PSRLW_XMMRG_IMM8                             0x0010710F        
#define X86IM_GEN_CODE_PSRLD_XMMRG_IMM8                             0x0010720F           
#define X86IM_GEN_CODE_PSRLQ_XMMRG_IMM8                             0x00D0730F          

#define X86IM_GEN_PSRLW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRLW_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSRLD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRLD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSRLQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSRLQ_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSRLW_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLW_XMMRG_IMM8, xmrg, 0, 0, imm8 )
#define X86IM_GEN_PSRLD_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLD_XMMRG_IMM8, xmrg, 0, 0, imm8 )
#define X86IM_GEN_PSRLQ_XMMRG_IMM8( io, mode, xmrg, imm8 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSRLQ_XMMRG_IMM8, xmrg, 0, 0, imm8 )

#define X86IM_GEN_CODE_PSUBQ_MMXR1_MMXR2                            0x00C0FB0F          
#define X86IM_GEN_CODE_PSUBQ_MMXRG_MM64                             0x0000FB0F
#define X86IM_GEN_CODE_PSUBQ_XMMR1_XMMR2                            0x00C0FB0F                 
#define X86IM_GEN_CODE_PSUBQ_XMMRG_MM                               0x0000FB0F

#define X86IM_GEN_PSUBQ_MMXR1_MMXR2( io, mode, mxr1, xmr2 )         x86im_gen( io, mode, X86IM_GEN_CODE_PSUBQ_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBQ_MMXRG_MM64( io, mode, mxrg, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_PSUBQ_MMXRG_MM64, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSUBQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSUBQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBQ_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSUBQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PSUBX_XMMR1_XMMR2                            0x00C0F80F    
#define X86IM_GEN_CODE_PSUBX_XMMRG_MM                               0x0000F80F

#define X86IM_GEN_PSUBB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBB_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSUBW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBW_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSUBD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSUBX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSUBX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PSUBSX_XMMR1_XMMR2                           0x00C0E80F    
#define X86IM_GEN_CODE_PSUBSX_XMMRG_MM                              0x0000E80F

#define X86IM_GEN_PSUBSB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBSB_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSUBSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBSW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
 
#define X86IM_GEN_CODE_PSUBUSX_XMMR1_XMMR2                          0x00C0D80F                 
#define X86IM_GEN_CODE_PSUBUSX_XMMRG_MM                             0x0000D80F

#define X86IM_GEN_PSUBUSB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBUSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBUSB_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSUBUSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSUBUSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBUSX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSUBUSW_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSUBUSX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PUNPCKHXX_XMMR1_XMMR2                        0x00C0680F  
#define X86IM_GEN_CODE_PUNPCKHXX_XMMRG_MM                           0x0000680F

#define X86IM_GEN_PUNPCKHBW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKHXX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKHBW_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKHXX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PUNPCKHWD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKHXX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKHWD_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKHXX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PUNPCKHDQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKHXX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKHDQ_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKHXX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PUNPCKHQDQ_XMMR1_XMMR2                       0x00C06D0F          
#define X86IM_GEN_CODE_PUNPCKHQDQ_XMMRG_MM                          0x00006D0F

#define X86IM_GEN_PUNPCKHQDQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )    x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PUNPCKHQDQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKHQDQ_XMMRG_MM( io, mode, xmrg, mm )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PUNPCKHQDQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PUNPCKLXX_XMMR1_XMMR2                        0x00C0600F            
#define X86IM_GEN_CODE_PUNPCKLXX_XMMRG_MM                           0x0000600F

#define X86IM_GEN_PUNPCKLBW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKLXX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKLBW_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_BW, X86IM_GEN_CODE_PUNPCKLXX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PUNPCKLWD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKLXX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKLWD_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_WD, X86IM_GEN_CODE_PUNPCKLXX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PUNPCKLDQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKLXX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKLDQ_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_DQ, X86IM_GEN_CODE_PUNPCKLXX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PUNPCKLQDQ_XMMR1_XMMR2                       0x00C06C0F           
#define X86IM_GEN_CODE_PUNPCKLQDQ_XMMRG_MM                          0x00006C0F

#define X86IM_GEN_PUNPCKLQDQ_XMMR1_XMMR2( io, mode, xmr1, xmr2 )    x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PUNPCKLQDQ_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PUNPCKLQDQ_XMMRG_MM( io, mode, xmrg, mm )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PUNPCKLQDQ_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PXOR_XMMR1_XMMR2                             0x00C0EF0F               
#define X86IM_GEN_CODE_PXOR_XMMRG_MM                                0x0000EF0F   

#define X86IM_GEN_PXOR_XMMR1_XMMR2( io, mode, xmr1, xmr2 )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PXOR_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 ) 
#define X86IM_GEN_PXOR_XMMRG_MM( io, mode, xmrg, mm )               x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PXOR_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

// SSE3                                 

#define X86IM_GEN_CODE_MONITOR                                      0x00C8010F                  
#define X86IM_GEN_MONITOR( io, mode )                               x86im_gen( io, mode, X86IM_GEN_CODE_MONITOR, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_MWAIT                                        0x00C9010F                  
#define X86IM_GEN_MWAIT( io, mode )                                 x86im_gen( io, mode, X86IM_GEN_CODE_MWAIT, 0, 0, 0, 0 )

#define X86IM_GEN_CODE_LDDQU_XMMRG_MM                               0x0000F00F               
#define X86IM_GEN_LDDQU_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_LDDQU_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ADDSUBPD_XMMR1_XMMR2                         0x00C0D00F        
#define X86IM_GEN_CODE_ADDSUBPD_XMMRG_MM                            0x0000D00F

#define X86IM_GEN_ADDSUBPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ADDSUBPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ADDSUBPD_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_ADDSUBPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_ADDSUBPS_XMMR1_XMMR2                         0x00C0D00F              
#define X86IM_GEN_CODE_ADDSUBPS_XMMRG_MM                            0x0000D00F

#define X86IM_GEN_ADDSUBPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_ADDSUBPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_ADDSUBPS_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_ADDSUBPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_HADDPD_XMMR1_XMMR2                           0x00C07C0F                 
#define X86IM_GEN_CODE_HADDPD_XMMRG_MM                              0x00007C0F 

#define X86IM_GEN_HADDPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_HADDPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_HADDPD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_HADDPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_HADDPS_XMMR1_XMMR2                           0x00C07C0F        
#define X86IM_GEN_CODE_HADDPS_XMMRG_MM                              0x00007C0F

#define X86IM_GEN_HADDPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_HADDPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_HADDPS_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_HADDPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_HSUBPD_XMMR1_XMMR2                           0x00C07D0F                
#define X86IM_GEN_CODE_HSUBPD_XMMRG_MM                              0x00007D0F

#define X86IM_GEN_HSUBPD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_HSUBPD_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_HSUBPD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_HSUBPD_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_HSUBPS_XMMR1_XMMR2                           0x00C07D0F                
#define X86IM_GEN_CODE_HSUBPS_XMMRG_MM                              0x00007D0F

#define X86IM_GEN_HSUBPS_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_HSUBPS_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_HSUBPS_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_HSUBPS_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVDDUP_XMMR1_XMMR2                          0x00C0120F             
#define X86IM_GEN_CODE_MOVDDUP_XMMRG_MM64                           0x0000120F

#define X86IM_GEN_MOVDDUP_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MOVDDUP_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVDDUP_XMMRG_MM64( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_F2, X86IM_GEN_CODE_MOVDDUP_XMMRG_MM64, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVSHDUP_XMMR1_XMMR2                         0x00C0160F             
#define X86IM_GEN_CODE_MOVSHDUP_XMMRG_MM                            0x0000160F

#define X86IM_GEN_MOVSHDUP_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSHDUP_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSHDUP_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSHDUP_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_MOVSLDUP_XMMR1_XMMR2                         0x00C0120F    
#define X86IM_GEN_CODE_MOVSLDUP_XMMRG_MM                            0x0000120F

#define X86IM_GEN_MOVSLDUP_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSLDUP_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_MOVSLDUP_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_F3, X86IM_GEN_CODE_MOVSLDUP_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PABSB_MMXR1_MMXR2                            0xC01C380F              
#define X86IM_GEN_CODE_PABSB_MMXRG_MM                               0x001C380F
#define X86IM_GEN_CODE_PABSB_XMMR1_XMMR2                            0xC01C380F           
#define X86IM_GEN_CODE_PABSB_XMMRG_MM                               0x001C380F

#define X86IM_GEN_PABSB_MMXR1_MMXR2( io, mode, mxr1, xmr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PABSB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PABSB_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PABSB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PABSW_MMXR1_MMXR2( io, mode, mxr1, xmr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PABSB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PABSW_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PABSB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PABSD_MMXR1_MMXR2( io, mode, mxr1, xmr2 )         x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PABSB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PABSD_MMXRG_MM( io, mode, mxrg, mm )              x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PABSB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_PABSB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PABSB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PABSB_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PABSB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PABSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PABSB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PABSW_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PABSB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PABSD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )         x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PABSB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PABSD_XMMRG_MM( io, mode, xmrg, mm )              x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PABSB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PALIGNR_MMXR1_MMXR2_IMM8                             0xC00F3A0F        
#define X86IM_GEN_CODE_PALIGNR_MMXRG_MM_IMM8                                0x000F3A0F
#define X86IM_GEN_CODE_PALIGNR_XMMR1_XMMR2_IMM8                             0xC00F3A0F  
#define X86IM_GEN_CODE_PALIGNR_XMMRG_MM_IMM8                                0x000F3A0F

#define X86IM_GEN_PALIGNR_MMXR1_MMXR2_IMM8( io, mode, mxr1, mxr2, imm8 )    x86im_gen( io, mode, X86IM_GEN_CODE_PALIGNR_MMXR1_MMXR2_IMM8, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, imm8 )
#define X86IM_GEN_PALIGNR_MMXRG_MM_IMM8( io, mode, mxrg, mm, imm8 )         x86im_gen( io, mode, X86IM_GEN_CODE_PALIGNR_MMXRG_MM_IMM8, X86IM_GEN_MXRG_MM( mxrg ), mm, imm8 )
#define X86IM_GEN_PALIGNR_XMMR1_XMMR2_IMM8( io, mode, xmr1, xmr2, imm8 )    x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PALIGNR_XMMR1_XMMR2_IMM8, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, imm8 )
#define X86IM_GEN_PALIGNR_XMMRG_MM_IMM8( io, mode, xmrg, mm, imm8 )         x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PALIGNR_XMMRG_MM_IMM8, X86IM_GEN_XMRG_MM( xmrg ), mm, imm8 )

#define X86IM_GEN_CODE_PHADDSW_MMXR1_MMXR2                          0xC003380F          
#define X86IM_GEN_CODE_PHADDSW_MMXRG_MM                             0x0003380F  
#define X86IM_GEN_CODE_PHADDSW_XMMR1_XMMR2                          0xC003380F  
#define X86IM_GEN_CODE_PHADDSW_XMMRG_MM                             0x0003380F

#define X86IM_GEN_PHADDSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode, X86IM_GEN_CODE_PHADDSW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PHADDSW_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_PHADDSW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PHADDSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PHADDSW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PHADDSW_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PHADDSW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PHSUBSW_MMXR1_MMXR2                          0xC007380F  
#define X86IM_GEN_CODE_PHSUBSW_MMXRG_MM                             0x0007380F  
#define X86IM_GEN_CODE_PHSUBSW_XMMR1_XMMR2                          0xC007380F  
#define X86IM_GEN_CODE_PHSUBSW_XMMRG_MM                             0x0007380F

#define X86IM_GEN_PHSUBSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )       x86im_gen( io, mode, X86IM_GEN_CODE_PHSUBSW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PHSUBSW_MMXRG_MM( io, mode, mxrg, mm )            x86im_gen( io, mode, X86IM_GEN_CODE_PHSUBSW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PHSUBSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )       x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PHSUBSW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PHSUBSW_XMMRG_MM( io, mode, xmrg, mm )            x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PHSUBSW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMADDUBSW_MMXR1_MMXR2                        0xC004380F        
#define X86IM_GEN_CODE_PMADDUBSW_MMXRG_MM                           0x0004380F
#define X86IM_GEN_CODE_PMADDUBSW_XMMR1_XMMR2                        0xC004380F  
#define X86IM_GEN_CODE_PMADDUBSW_XMMRG_MM                           0x0004380F

#define X86IM_GEN_PMADDUBSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )     x86im_gen( io, mode, X86IM_GEN_CODE_PMADDUBSW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMADDUBSW_MMXRG_MM( io, mode, mxrg, mm )          x86im_gen( io, mode, X86IM_GEN_CODE_PMADDUBSW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PMADDUBSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )     x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMADDUBSW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMADDUBSW_XMMRG_MM( io, mode, xmrg, mm )          x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMADDUBSW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PMULHRSW_MMXR1_MMXR2                         0xC00B380F           
#define X86IM_GEN_CODE_PMULHRSW_MMXRG_MM                            0x000B380F  
#define X86IM_GEN_CODE_PMULHRSW_XMMR1_XMMR2                         0xC00B380F      
#define X86IM_GEN_CODE_PMULHRSW_XMMRG_MM                            0x000B380F

#define X86IM_GEN_PMULHRSW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )      x86im_gen( io, mode, X86IM_GEN_CODE_PMULHRSW_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULHRSW_MMXRG_MM( io, mode, mxrg, mm )           x86im_gen( io, mode, X86IM_GEN_CODE_PMULHRSW_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PMULHRSW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )      x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULHRSW_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PMULHRSW_XMMRG_MM( io, mode, xmrg, mm )           x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PMULHRSW_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PSHUFB_MMXR1_MMXR2                           0x00C0380F              
#define X86IM_GEN_CODE_PSHUFB_MMXRG_MM                              0x0000380F
#define X86IM_GEN_CODE_PSHUFB_XMMR1_XMMR2                           0x0C00380F  
#define X86IM_GEN_CODE_PSHUFB_XMMRG_MM                              0x0000380F

#define X86IM_GEN_PSHUFB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode, X86IM_GEN_CODE_PSHUFB_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSHUFB_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode, X86IM_GEN_CODE_PSHUFB_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSHUFB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSHUFB_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSHUFB_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66, X86IM_GEN_CODE_PSHUFB_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PSIGNX_MMXR1_MMXR2                           0xC008380F  
#define X86IM_GEN_CODE_PSIGNX_MMXRG_MM                              0x0008380F
#define X86IM_GEN_CODE_PSIGNX_XMMR1_XMMR2                           0xC008380F  
#define X86IM_GEN_CODE_PSIGNX_XMMRG_MM                              0x0008380F

#define X86IM_GEN_PSIGNB_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSIGNX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSIGNB_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSIGNX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSIGNW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSIGNX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSIGNW_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSIGNX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PSIGND_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSIGNX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PSIGND_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSIGNX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_PSIGNB_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSIGNX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSIGNB_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_B, X86IM_GEN_CODE_PSIGNX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSIGNW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSIGNX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSIGNW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PSIGNX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PSIGND_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSIGNX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PSIGND_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PSIGNX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PHADDX_MMXR1_MMXR2                           0x00C0380F           
#define X86IM_GEN_CODE_PHADDX_MMXRG_MM                              0x0000380F  
#define X86IM_GEN_CODE_PHADDX_XMMR1_XMMR2                           0x00C0380F         
#define X86IM_GEN_CODE_PHADDX_XMMRG_MM                              0x0000380F              

#define X86IM_GEN_PHADDW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHADDX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PHADDW_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHADDX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PHADDD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHADDX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PHADDD_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHADDX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_PHADDW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHADDX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PHADDW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHADDX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PHADDD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHADDX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PHADDD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHADDX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#define X86IM_GEN_CODE_PHSUBX_MMXR1_MMXR2                           0xC004380F              
#define X86IM_GEN_CODE_PHSUBX_MMXRG_MM                              0x0004380F  
#define X86IM_GEN_CODE_PHSUBX_XMMR1_XMMR2                           0xC004380F           
#define X86IM_GEN_CODE_PHSUBX_XMMRG_MM                              0x0004380F

#define X86IM_GEN_PHSUBW_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHSUBX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PHSUBW_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHSUBX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )
#define X86IM_GEN_PHSUBD_MMXR1_MMXR2( io, mode, mxr1, mxr2 )        x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHSUBX_MMXR1_MMXR2, X86IM_GEN_MXR1_MXR2( mxr1, mxr2 ), 0, 0, 0 )
#define X86IM_GEN_PHSUBD_MMXRG_MM( io, mode, mxrg, mm )             x86im_gen( io, mode|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHSUBX_MMXRG_MM, X86IM_GEN_MXRG_MM( mxrg ), mm, 0 )

#define X86IM_GEN_PHSUBW_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHSUBX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PHSUBW_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_W, X86IM_GEN_CODE_PHSUBX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )
#define X86IM_GEN_PHSUBD_XMMR1_XMMR2( io, mode, xmr1, xmr2 )        x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHSUBX_XMMR1_XMMR2, X86IM_GEN_XMR1_XMR2( xmr1, xmr2 ), 0, 0, 0 )
#define X86IM_GEN_PHSUBD_XMMRG_MM( io, mode, xmrg, mm )             x86im_gen( io, mode|X86IM_IO_IP_66|X86IM_GEN_OAT_PO_D, X86IM_GEN_CODE_PHSUBX_XMMRG_MM, X86IM_GEN_XMRG_MM( xmrg ), mm, 0 )

#endif // __X86IM_GEN_H__
