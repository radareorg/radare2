//////////////////////////////////////////////////////////////
//
// x86 Instruction Manipulator: Decoder/Generator/Encoder v1.0
//
// (x) Pluf
//
//////////////////////////////////////////////////////////////

#ifndef __X86IM_ITBL_H__
#define __X86IM_ITBL_H__

#define ITE_MAX_OP                          3

typedef struct _x86im_itbl_entry
{
    unsigned short id;
    unsigned short grp;
    unsigned short mnm;
    unsigned short len;
    unsigned long flags;
    unsigned long extflg;
    unsigned short rop[ ITE_MAX_OP ];

} x86im_itbl_entry;

#define _ITE_ENC_DEF                        0x00000000
#define _ITE_ENC_I64                        0x00000001
#define _ITE_ENC_O64                        0x00000002
#define _ITE_ENC_D64                        0x00000004
#define _ITE_ENC_FIM                        0x00000008
#define _ITE_ENC_NS                         0x00000010
#define _ITE_ENC_F8                         0x00000020
#define _ITE_ENC_F16                        0x00000040
#define _ITE_ENC_F32                        0x00000080
#define _ITE_ENC_F64                        0x00000100
#define _ITE_ENC_MO                         0x00000400

#define ITE_ENC_I64(x)                      ( (x)->flags & _ITE_ENC_I64 )
#define ITE_ENC_O64(x)                      ( (x)->flags & _ITE_ENC_O64 )
#define ITE_ENC_D64(x)                      ( (x)->flags & _ITE_ENC_D64 )
#define ITE_ENC_FIM(x)                      ( (x)->flags & _ITE_ENC_FIM )
#define ITE_ENC_NS(x)                       ( (x)->flags & _ITE_ENC_NS  )
#define ITE_ENC_FIXED(x)                    ( (x)->flags & (_ITE_ENC_F8|_ITE_ENC_F16|_ITE_ENC_F32|_ITE_ENC_F64) )
#define ITE_ENC_F8(x)                       ( (x)->flags & _ITE_ENC_F8  )
#define ITE_ENC_F16(x)                      ( (x)->flags & _ITE_ENC_F16 )
#define ITE_ENC_F32(x)                      ( (x)->flags & _ITE_ENC_F32 )
#define ITE_ENC_F64(x)                      ( (x)->flags & _ITE_ENC_F64 )
#define ITE_ENC_MO(x)                       ( (x)->flags & _ITE_ENC_MO )
#define ITE_ENC_ISM(c,x)                    ( ( (c) & 0xC0 ) == 0xC0 )
#define ITE_ENC(b)                          ( (b) )

#define _ITE_BIT_WB                         0x00000001
#define _ITE_BIT_SB                         0x00000002
#define _ITE_BIT_W3                         0x00000004
#define _ITE_BIT_DB                         0x00000008
#define _ITE_BIT_NZ                         0x00000010
#define _ITE_BIT_NC                         0x00000020
#define _ITE_BIT_GG                         0x00000040
#define _ITE_BIT_MB                         0x00000080

#define ITE_HAS_BIT(x)                      ( (x)->extflg & 0x000000FF   )
#define ITE_BIT_WX(x)                       ( (x)->extflg & (_ITE_BIT_WB|_ITE_BIT_W3) )
#define ITE_BIT_WB(x)                       ( (x)->extflg & _ITE_BIT_WB  )
#define ITE_BIT_W3(x)                       ( (x)->extflg & _ITE_BIT_W3  )
#define ITE_BIT_SB(x)                       ( (x)->extflg & _ITE_BIT_SB  )
#define ITE_BIT_DB(x)                       ( (x)->extflg & _ITE_BIT_DB  )
#define ITE_BIT_NZ(x)                       ( (x)->extflg & _ITE_BIT_NZ  )
#define ITE_BIT_NC(x)                       ( (x)->extflg & _ITE_BIT_NC  )
#define ITE_BIT_GG(x)                       ( (x)->extflg & _ITE_BIT_GG  )
#define ITE_BIT_MB(x)                       ( (x)->extflg & _ITE_BIT_MB  )
#define ITE_BIT(b)                          ( (b) )

#define _ITE_REX                            0x00004000
#define _ITE_REX_W                          0x00000800
#define _ITE_REX_R                          0x00000400
#define _ITE_REX_X                          0x00000200
#define _ITE_REX_B                          0x00000100

#define ITE_REX_W(x)                        ( ( (x)->extflg & _ITE_REX_W ) >> (8+3) )
#define ITE_REX_R(x)                        ( ( (x)->extflg & _ITE_REX_R ) >> (8+2) )
#define ITE_REX_X(x)                        ( ( (x)->extflg & _ITE_REX_X ) >> (8+1) )
#define ITE_REX_B(x)                        ( ( (x)->extflg & _ITE_REX_B ) >> (8+0) )
#define ITE_REX(r)                          ( _ITE_REX | (r) )

#define _ITE_PFX_LOCK                       0x00010000
#define _ITE_PFX_REPE                       0x00020000
#define _ITE_PFX_REPN                       0x00040000
#define _ITE_PFX_OPSZ                       0x00080000
#define _ITE_PFX_ADSZ                       0x00100000
#define _ITE_PFX_SGXX                       0x00200000

#define ITE_PFX_LOCK(x)                     ( ( (x)->extflg & _ITE_PFX_LOCK ) >> 16 )
#define ITE_PFX_REPE(x)                     ( ( (x)->extflg & _ITE_PFX_REPE ) >> 16 )
#define ITE_PFX_REPN(x)                     ( ( (x)->extflg & _ITE_PFX_REPN ) >> 16 )
#define ITE_PFX_OPSZ(x)                     ( ( (x)->extflg & _ITE_PFX_OPSZ ) >> 16 )
#define ITE_PFX_ADSZ(x)                     ( ( (x)->extflg & _ITE_PFX_ADSZ ) >> 16 )
#define ITE_FPX_SGXX(x)                     ( ( (x)->extflg & _ITE_PFX_SGXX ) >> 16 )
#define ITE_PFX(p)                          ( (p) )

#define _ITE_SOMI                           0x80000000
#define _ITE_SOMI_BASE                      0x01000000
#define _ITE_SOMI_MP_66                     0x08000000
#define _ITE_SOMI_MP_F2                     0x04000000
#define _ITE_SOMI_MP_F3                     0x02000000

#define ITE_IS_SOMI(x)                      ( ( (x)->extflg >> 24 ) & 0x80 )
#define ITE_SOMI_BASE(x)                    ( ( (x)->extflg & _ITE_SOMI_BASE ) >> 24 )
#define ITE_SOMI_MP(x)                      ( ( (x)->extflg & (_ITE_SOMI_66|_ITE_SOMI_F2|_ITE_SOMI_F3 ) ) >> 24 )
#define ITE_SOMI_MP_66(x)                   ( ( (x)->extflg & _ITE_SOMI_66 ) >> 24 )
#define ITE_SOMI_MP_F2(x)                   ( ( (x)->extflg & _ITE_SOMI_F2 ) >> 24 )
#define ITE_SOMI_MP_F3(x)                   ( ( (x)->extflg & _ITE_SOMI_F3 ) >> 24 )
#define ITE_SOMI(p)                         ( ( _ITE_SOMI | (p) ) )

#define ITE_NOOP                            0xDEAD

#define ITE_EOP                             0x4000
#define ITE_IOP                             0x2000

#define ITE_IS_EOP(x)                       ( (x) & ITE_EOP )
#define ITE_IS_IOP(x)                       ( (x) & ITE_IOP )

#define ITE_EOP_REG                         0x0100
#define ITE_EOP_MEM                         0x0200
#define ITE_EOP_RM                          0x0400
#define ITE_EOP_IMM                         0x0800
#define ITE_EOP_SP                          0x1000

#define ITE_IS_EOP_REG(x)                   ( (x) & ITE_EOP_REG )
#define ITE_IS_EOP_MEM(x)                   ( (x) & ITE_EOP_MEM )
#define ITE_IS_EOP_RM(x)                    ( (x) & ITE_EOP_RM  )
#define ITE_IS_EOP_IMM(x)                   ( (x) & ITE_EOP_IMM )
#define ITE_IS_EOP_SP(x)                    ( (x) & ITE_EOP_SP  )

#define ITE_EO_MRRMD                        ( ITE_EOP | ( ITE_EOP_REG + 0  ) )
#define ITE_EO_MRRGS                        ( ITE_EOP | ( ITE_EOP_REG + 1  ) )
#define ITE_EO_MRRMS                        ( ITE_EOP | ( ITE_EOP_REG + 2  ) )
#define ITE_EO_MRRGD                        ( ITE_EOP | ( ITE_EOP_REG + 3  ) )
#define ITE_EO_MRRMS8                       ( ITE_EOP | ( ITE_EOP_REG + 4  ) )
#define ITE_EO_MRRMD8                       ( ITE_EOP | ( ITE_EOP_REG + 5  ) )
#define ITE_EO_MRRMS16                      ( ITE_EOP | ( ITE_EOP_REG + 6  ) )
#define ITE_EO_MRRMD16                      ( ITE_EOP | ( ITE_EOP_REG + 7  ) )
#define ITE_EO_MRCX                         ( ITE_EOP | ( ITE_EOP_REG + 8  ) )
#define ITE_EO_MRDX                         ( ITE_EOP | ( ITE_EOP_REG + 9  ) )
#define ITE_EO_MRSX                         ( ITE_EOP | ( ITE_EOP_REG + 10 ) )
#define ITE_EO_ORS2                         ( ITE_EOP | ( ITE_EOP_REG + 11 ) )
#define ITE_EO_ORS3                         ( ITE_EOP | ( ITE_EOP_REG + 24 ) )
#define ITE_EO_ORAD                         ( ITE_EOP | ( ITE_EOP_REG + 12 ) )
#define ITE_EO_ORAS                         ( ITE_EOP | ( ITE_EOP_REG + 13 ) )
#define ITE_EO_MRSTXS                       ( ITE_EOP | ( ITE_EOP_REG + 14 ) )
#define ITE_EO_MRSTXD                       ( ITE_EOP | ( ITE_EOP_REG + 15 ) )
#define ITE_EO_MRRMMXD                      ( ITE_EOP | ( ITE_EOP_REG + 16 ) )
#define ITE_EO_MRRGMXS                      ( ITE_EOP | ( ITE_EOP_REG + 17 ) )
#define ITE_EO_MRRMMXS                      ( ITE_EOP | ( ITE_EOP_REG + 18 ) )
#define ITE_EO_MRRGMXD                      ( ITE_EOP | ( ITE_EOP_REG + 19 ) )
#define ITE_EO_MRRMXMD                      ( ITE_EOP | ( ITE_EOP_REG + 20 ) )
#define ITE_EO_MRRGXMS                      ( ITE_EOP | ( ITE_EOP_REG + 21 ) )
#define ITE_EO_MRRMXMS                      ( ITE_EOP | ( ITE_EOP_REG + 22 ) )
#define ITE_EO_MRRGXMD                      ( ITE_EOP | ( ITE_EOP_REG + 23 ) )

#define ITE_EO_MMS                          ( ITE_EOP | ( ITE_EOP_MEM + 0  ) )
#define ITE_EO_MMD                          ( ITE_EOP | ( ITE_EOP_MEM + 1  ) )
#define ITE_EO_MMS8                         ( ITE_EOP | ( ITE_EOP_MEM + 2  ) )
#define ITE_EO_MMD8                         ( ITE_EOP | ( ITE_EOP_MEM + 3  ) )
#define ITE_EO_MMS16                        ( ITE_EOP | ( ITE_EOP_MEM + 4  ) )
#define ITE_EO_MMD16                        ( ITE_EOP | ( ITE_EOP_MEM + 5  ) )
#define ITE_EO_MMS32                        ( ITE_EOP | ( ITE_EOP_MEM + 6  ) )
#define ITE_EO_MMD32                        ( ITE_EOP | ( ITE_EOP_MEM + 7  ) )
#define ITE_EO_MMS64                        ( ITE_EOP | ( ITE_EOP_MEM + 8  ) )
#define ITE_EO_MMD64                        ( ITE_EOP | ( ITE_EOP_MEM + 9  ) )
#define ITE_EO_MMS80                        ( ITE_EOP | ( ITE_EOP_MEM + 10 ) )
#define ITE_EO_MMD80                        ( ITE_EOP | ( ITE_EOP_MEM + 11 ) )
#define ITE_EO_MMS128                       ( ITE_EOP | ( ITE_EOP_MEM + 12 ) )
#define ITE_EO_MMD128                       ( ITE_EOP | ( ITE_EOP_MEM + 13 ) )
#define ITE_EO_MMFP                         ( ITE_EOP | ( ITE_EOP_MEM + 14 ) )
#define ITE_EO_FPU_ST                       ( ITE_EOP | ( ITE_EOP_MEM + 15 ) )
#define ITE_EO_FPU_ENV                      ( ITE_EOP | ( ITE_EOP_MEM + 16 ) )
#define ITE_EO_FPU_XST                      ( ITE_EOP | ( ITE_EOP_MEM + 17 ) )
#define ITE_EO_BNDMMS                       ( ITE_EOP | ( ITE_EOP_MEM + 18 ) )
#define ITE_EO_MMDTRS                       ( ITE_EOP | ( ITE_EOP_MEM + 19 ) )
#define ITE_EO_MMDTRD                       ( ITE_EOP | ( ITE_EOP_MEM + 20 ) )
#define ITE_EO_MMFD                         ( ITE_EOP | ( ITE_EOP_MEM + 21 ) )

#define ITE_EO_SRGMM                        ( ITE_EOP | ( ITE_EOP_RM + 0  ) )
#define ITE_EO_SRGMM8                       ( ITE_EOP | ( ITE_EOP_RM + 14 ) )
#define ITE_EO_SRG8MM8                      ( ITE_EOP | ( ITE_EOP_RM + 13 ) )
#define ITE_EO_SRGMM16                      ( ITE_EOP | ( ITE_EOP_RM + 15 ) )
#define ITE_EO_SRG16MM16                    ( ITE_EOP | ( ITE_EOP_RM + 1  ) )
#define ITE_EO_DRGMM                        ( ITE_EOP | ( ITE_EOP_RM + 2  ) )
#define ITE_EO_DRGMM16                      ( ITE_EOP | ( ITE_EOP_RM + 12 ) )
#define ITE_EO_DRG16MM16                    ( ITE_EOP | ( ITE_EOP_RM + 16 ) )
#define ITE_EO_MXSRGMM                      ( ITE_EOP | ( ITE_EOP_RM + 3  ) )
#define ITE_EO_MXSRGMM32                    ( ITE_EOP | ( ITE_EOP_RM + 4  ) )
#define ITE_EO_MXDRGMM                      ( ITE_EOP | ( ITE_EOP_RM + 5  ) )
#define ITE_EO_XMSRGMM                      ( ITE_EOP | ( ITE_EOP_RM + 6  ) )
#define ITE_EO_XMSRGMM32                    ( ITE_EOP | ( ITE_EOP_RM + 7  ) )
#define ITE_EO_XMSRGMM64                    ( ITE_EOP | ( ITE_EOP_RM + 8  ) )
#define ITE_EO_XMDRGMM                      ( ITE_EOP | ( ITE_EOP_RM + 9  ) )
#define ITE_EO_XMDRGMM32                    ( ITE_EOP | ( ITE_EOP_RM + 10 ) )
#define ITE_EO_XMDRGMM64                    ( ITE_EOP | ( ITE_EOP_RM + 11 ) )

#define ITE_EO_IMMO                         ( ITE_EOP | ( ITE_EOP_IMM + 3  ) )
#define ITE_EO_IMMO8                        ( ITE_EOP | ( ITE_EOP_IMM + 1  ) )
#define ITE_EO_IMMO16                       ( ITE_EOP | ( ITE_EOP_IMM + 2  ) )
#define ITE_EO_IMMO32                       ( ITE_EOP | ( ITE_EOP_IMM + 4  ) )
#define ITE_EO_IMM2O24                      ( ITE_EOP | ( ITE_EOP_IMM + 5  ) )
#define ITE_EO_IMMR                         ( ITE_EOP | ( ITE_EOP_IMM + 6  ) )
#define ITE_EO_IMMR8                        ( ITE_EOP | ( ITE_EOP_IMM + 7  ) )
#define ITE_EO_IMMM                         ( ITE_EOP | ( ITE_EOP_IMM + 8  ) )
#define ITE_EO_IMMM8                        ( ITE_EOP | ( ITE_EOP_IMM + 9  ) )
#define ITE_EO_IMMRGMM                      ( ITE_EOP | ( ITE_EOP_IMM + 10 ) )
#define ITE_EO_IMMRGMM8                     ( ITE_EOP | ( ITE_EOP_IMM + 11 ) )
#define ITE_EO_IMMSL                        ( ITE_EOP | ( ITE_EOP_IMM + 13 ) )

#define ITE_EO_SOTTTN                       ( ITE_EOP | ( ITE_EOP_SP + 0 ) )
#define ITE_EO_ARPLOP1                      ( ITE_EOP | ( ITE_EOP_SP + 1 ) )
#define ITE_EO_ARPLOP2                      ( ITE_EOP | ( ITE_EOP_SP + 2 ) )
#define ITE_EO_CMPXCHG                      ( ITE_EOP | ( ITE_EOP_SP + 3 ) )

#define ITE_IO_IRAS                         ( ITE_IOP + 0 )
#define ITE_IO_IRAD                         ( ITE_IOP + 1 )
#define ITE_IO_MRST0S                       ( ITE_IOP + 2 )
#define ITE_IO_MRST0D                       ( ITE_IOP + 3 )
#define ITE_IO_MRST0                        ( ITE_IOP + 4 )
#define ITE_IO_MRST1                        ( ITE_IOP + 5 )
#define ITE_IO_RC8S                         ( ITE_IOP + 6 )
#define ITE_IO_RD16S                        ( ITE_IOP + 7 )
#define ITE_IO_IMM1                         ( ITE_IOP + 8 )

#define X86IM_FPU                           0xF000
#define ITE_INV                             0xF001
#define X86IM_GRP                           0xF002
#define X86IM_2BYTE                         0xF003
#define X86IM_PFX                           0xF004
#define ITE_NOGRP                           0xF004
#define ITE_NOIMN                           0xF005

#define ITE_GRP_80                          0
#define ITE_GRP_81                          1
#define ITE_GRP_82                          2
#define ITE_GRP_83                          3
#define ITE_GRP_8F                          4
#define ITE_GRP_C0                          5
#define ITE_GRP_C1                          6
#define ITE_GRP_C6                          7
#define ITE_GRP_C7                          8
#define ITE_GRP_D0                          9
#define ITE_GRP_D1                          10
#define ITE_GRP_D2                          11
#define ITE_GRP_D3                          12
#define ITE_GRP_F6                          13
#define ITE_GRP_F7                          14
#define ITE_GRP_FE                          15
#define ITE_GRP_FF                          16

#define ITE_GRP_0F_00                       0
#define ITE_GRP_0F_01                       4
#define ITE_GRP_0F_18                       8
#define ITE_GRP_0F_71                       12
#define ITE_GRP_0F_72                       16
#define ITE_GRP_0F_73                       20
#define ITE_GRP_0F_AE                       24
#define ITE_GRP_0F_BA                       28
#define ITE_GRP_0F_C7                       32

#define X86IM_FPU_D8	                    0
#define X86IM_FPU_D9	                    1
#define X86IM_FPU_DA	                    2
#define X86IM_FPU_DB	                    3
#define X86IM_FPU_DC	                    4
#define X86IM_FPU_DD	                    5
#define X86IM_FPU_DE	                    6
#define X86IM_FPU_DF	                    7

x86im_itbl_entry itbl_1byte_grp1_op_80[]=
{
{ X86IM_IO_ID_ADD_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,  
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT( _ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1, 
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB), 
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  }, 
{ X86IM_IO_ID_CMP_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_1byte_grp1_op_81[]=
{
{ X86IM_IO_ID_ADD_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,  
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1, 
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB), 
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  }, 
{ X86IM_IO_ID_CMP_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_1byte_grp1_op_82[]=
{
{ X86IM_IO_ID_ADD_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_I64), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_I64), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_I64), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_I64), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND, 
  1,
  ITE_ENC(_ITE_ENC_I64), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,  
  1,
  ITE_ENC(_ITE_ENC_I64), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT( _ITE_BIT_WB|_ITE_BIT_SB ),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1, 
  ITE_ENC(_ITE_ENC_I64), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT( _ITE_BIT_WB|_ITE_BIT_SB ), 
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  }, 
{ X86IM_IO_ID_CMP_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_I64), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_1byte_grp1_op_83[]=
{
{ X86IM_IO_ID_ADD_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,  
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT( _ITE_BIT_WB|_ITE_BIT_SB ),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_MM_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1, 
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT( _ITE_BIT_WB|_ITE_BIT_SB ), 
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  }, 
{ X86IM_IO_ID_CMP_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_1byte_grp1A_op_8F[]=
{
{ X86IM_IO_ID_POP_MM, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_1byte_grp2_op_C0[]=
{
{ X86IM_IO_ID_ROL_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_ROR_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_RCL_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_RCR_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SHR_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SAR_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  }
};

x86im_itbl_entry itbl_1byte_grp2_op_C1[]=
{
{ X86IM_IO_ID_ROL_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_ROR_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_RCL_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_RCR_MM_IM, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SHR_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_SAR_MM_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAR, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  }
};

x86im_itbl_entry itbl_1byte_grp11_op_C6[]=
{
{ X86IM_IO_ID_MOV_MM_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_1byte_grp11_op_C7[]=
{
{ X86IM_IO_ID_MOV_MM_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_1byte_grp2_op_D0[]=
{
{ X86IM_IO_ID_ROL_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_ROR_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_RCL_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_RCR_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SHR_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SAR_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  }
};

x86im_itbl_entry itbl_1byte_grp2_op_D1[]=
{
{ X86IM_IO_ID_ROL_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_ROR_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_RCL_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_RCR_MM_1, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SHR_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  },
{ X86IM_IO_ID_SAR_MM_1, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_IMM1, ITE_NOOP }
  }
};

x86im_itbl_entry itbl_1byte_grp2_op_D2[]=    
{
{ X86IM_IO_ID_ROL_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_ROR_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_RCL_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_RCR_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SHR_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SAR_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  }
};

x86im_itbl_entry itbl_1byte_grp2_op_D3[]=    
{
{ X86IM_IO_ID_ROL_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_ROR_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_ROR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_RCL_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_RCR_MM_CL, X86IM_IO_SGR_GPI_ROTAT, X86IM_IO_IMN_RCR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SHR_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SHL_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  },
{ X86IM_IO_ID_SAR_MM_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SAR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_IO_RC8S, ITE_NOOP }
  }
};

x86im_itbl_entry itbl_1byte_grp3_op_F6[]=
{
{ X86IM_IO_ID_TEST_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_TEST_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_NOT_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_NOT,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_NEG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_NEG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_MUL_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_MUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IMUL_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_IMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DIV_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IDIV_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_IDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_1byte_grp3_op_F7[]=
{
{ X86IM_IO_ID_TEST_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_TEST_MM_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_NOT_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_NOT,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_NEG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_NEG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_MUL_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_MUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IMUL_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_IMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DIV_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IDIV_AC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_IDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_1byte_grp4_op_FE[]=
{
{ X86IM_IO_ID_INC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_1byte_grp5_op_FF[]=
{
{ X86IM_IO_ID_INC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CALL_N_AI_MM, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_CALL,
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CALL_F_AI_MM, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_CALL_FAR,
  1,
  ITE_ENC(_ITE_ENC_DEF|_ITE_ENC_MO), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMFP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_JMP_N_AI_MM, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JMP,
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_SRGMM, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_JMP_F_AI_MM, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JMP_FAR,
  1,
  ITE_ENC(_ITE_ENC_DEF|_ITE_ENC_MO), 0,
  { ITE_EO_MMFP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_MM, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp6_op_0F_00[]=
{
{ X86IM_IO_ID_SLDT_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SLDT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_STR_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_STR, 
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LLDT_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_LLDT, 
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRG16MM16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LTR_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_LTR,  
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRG16MM16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_VERR_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_VERR, 
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRG16MM16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_VERW_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_VERW, 
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRG16MM16, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp16_op_0F_18[]=
{
{ X86IM_IO_ID_PREFETCHNTA, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_PREFETCH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_EO_MMS8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PREFETCHT0, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_PREFETCH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_EO_MMS8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PREFETCHT1, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_PREFETCH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_EO_MMS8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PREFETCHT2, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_PREFETCH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_EO_MMS8, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp12_op_0F_71[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRLW_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },  
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRAW_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRAW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLW_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSLLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp12_op_0F_71_pfx66[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRLW_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRAW_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRAW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLW_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSLLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp13_op_0F_72[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRLD_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRAD_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRAD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLD_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSLLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp13_op_0F_72_pfx66[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRLD_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRAD_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRAD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLD_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSLLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp14_op_0F_73[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRLQ_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLQ_MMXRG_IMM8, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSLLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMMXD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp14_op_0F_73_pfx66[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRLQ_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRLDQ_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRLDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLQ_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSLLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
{ X86IM_IO_ID_PSLLDQ_XMMRG_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSLLDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R),
  { ITE_EO_MRRMXMD, ITE_EO_IMMR8, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_grp15_op_0F_AE[]=
{
{ X86IM_IO_ID_FXSAVE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FXSAVE,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_FPU_XST, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FXRSTOR, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FXRSTOR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_FPU_XST, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LDMXCSR_MM32, X86IM_IO_SGR_SSE_STATE, X86IM_IO_IMN_LDMXCSR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD32, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_STMXCSR_MM32, X86IM_IO_SGR_SSE_STATE, X86IM_IO_IMN_STMXCSR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMS32, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CLFLUSH_MM8, X86IM_IO_SGR_SSE2_MISC, X86IM_IO_IMN_CLFLUSH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMS8, ITE_NOOP, ITE_NOOP }
  }
};

x86im_itbl_entry itbl_grp15_op_0F_AE_rm[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_LFENCE, X86IM_IO_SGR_SSE2_MISC, X86IM_IO_IMN_LFENCE,
  3,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_MFENCE, X86IM_IO_SGR_SSE2_MISC, X86IM_IO_IMN_MFENCE,
  3,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SFENCE, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_SFENCE,
  3,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_grp7_op_0F_01[]=
{
{ X86IM_IO_ID_SGDT, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SGDT, 
  2,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMDTRD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SIDT, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SIDT, 
  2,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMDTRD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LGDT, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_LGDT, 
  2,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMDTRS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LIDT, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_LIDT, 
  2,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMDTRS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SMSW_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SMSW, 
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM16, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_LMSW_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_LMSW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRG16MM16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INVLPG, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_INVLPG,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MMD8, ITE_NOOP, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_grp7_op_0F_01_reg1[]=    
{
{ X86IM_IO_ID_MONITOR, X86IM_IO_GR_SSE3, X86IM_IO_IMN_MONITOR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_MB),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_MWAIT, X86IM_IO_GR_SSE3, X86IM_IO_IMN_MWAIT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_MB),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp7_op_0F_01_reg7[]=    
{
{ X86IM_IO_ID_SWAPGS, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SWAPGS,
  2,
  ITE_ENC(_ITE_ENC_O64), ITE_BIT(_ITE_BIT_MB),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp8_op_0F_BA[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_BT_MM_IM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_BTS_MM_IM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BTS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_BTR_MM_IM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BTR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
{ X86IM_IO_ID_BTC_MM_IM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BTC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_IMMRGMM8, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_grp9_op_0F_C7[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CMPXCHGXX, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMPXCHGXX,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_EO_CMPXCHG, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_grp_invalid[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_1byte[]=
{
{ X86IM_IO_ID_ADD_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP } 
  },
{ X86IM_IO_ID_ADD_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK)| ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP } 
  },
{ X86IM_IO_ID_ADD_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADD_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADD_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_ADD_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_SR1, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORS2, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_SR1, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORS2, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_MM_RG, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_MM_RG, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_RG_MM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_RG_MM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_AC_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_OR_AC_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_OR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_SR1, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORS2, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_2BYTE, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_ADC_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADC_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP, }
  },
{ X86IM_IO_ID_ADC_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_ADC,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP, }
  },
{ X86IM_IO_ID_PUSH_SR1, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORS2, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_SR1, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORS2, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB), 
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_SBB_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SBB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB), 
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_SR1, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORS2, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_SR1, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORS2, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_MM_RG, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_MM_RG, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_RG_MM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_RG_MM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_AC_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_AND_AC_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_AND,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_DAA, X86IM_IO_SGR_GPI_DARITH, X86IM_IO_IMN_DAA,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_SUB_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_SUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_DAS, X86IM_IO_SGR_GPI_DARITH, X86IM_IO_IMN_DAS,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_MM_RG, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_MM_RG, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_RG_MM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_RG_MM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_AC_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_XOR_AC_IM, X86IM_IO_SGR_GPI_LOGIC, X86IM_IO_IMN_XOR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_AAA, X86IM_IO_SGR_GPI_DARITH, X86IM_IO_IMN_AAA,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CMP_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_CMP_MM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_CMP_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CMP_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CMP_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_CMP_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_CMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_AAS, X86IM_IO_SGR_GPI_DARITH, X86IM_IO_IMN_AAS,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_INC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_DEC_RG2, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_DEC,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_RG2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_ORAD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSHAD, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSHAD,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POPAD, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POPAD,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BOUND, X86IM_IO_SGR_GPI_MISC, X86IM_IO_IMN_BOUND,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_MRRGD, ITE_EO_BNDMMS, ITE_NOOP }
  },
{ X86IM_IO_ID_ARPL_MM_RG, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_ARPL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_EO_ARPLOP1, ITE_EO_ARPLOP2, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PUSH_IM, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_SB),
  { ITE_EO_IMMO, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IMUL_MM_IM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_IMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_SB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_EO_IMMRGMM }
  },
{ X86IM_IO_ID_PUSH_IM, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_SB),
  { ITE_EO_IMMO, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IMUL_MM_IM_RG, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_IMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_SB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_EO_IMMRGMM }
  },
{ X86IM_IO_ID_INSX, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_INS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INSX, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_INS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_OUTSX, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_OUTS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_OUTSX, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_OUTS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO8, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_80, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_81, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_82, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_83, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB|_ITE_BIT_SB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_TEST_MM_R1, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_TEST_MM_R1, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_MM_SR, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_DB),
  { ITE_EO_DRGMM16, ITE_EO_MRSX, ITE_NOOP }
  },
{ X86IM_IO_ID_LEA, X86IM_IO_SGR_GPI_MISC, X86IM_IO_IMN_LEA,
  1,
  ITE_ENC(_ITE_ENC_DEF|_ITE_ENC_MO), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MMS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_SR_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_F16), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_DB),
  { ITE_EO_MRSX, ITE_EO_SRG16MM16, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_8F, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_NOP, X86IM_IO_SGR_GPI_MISC, X86IM_IO_IMN_NOP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_F3),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_AC_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_IO_IRAD, ITE_EO_ORAS, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_AC_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_IO_IRAD, ITE_EO_ORAS, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_AC_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_IO_IRAD, ITE_EO_ORAS, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_AC_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_IO_IRAD, ITE_EO_ORAS, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_AC_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_IO_IRAD, ITE_EO_ORAS, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_AC_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_IO_IRAD, ITE_EO_ORAS, ITE_NOOP }
  },
{ X86IM_IO_ID_XCHG_AC_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XCHG,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_IO_IRAD, ITE_EO_ORAS, ITE_NOOP }
  },
{ X86IM_IO_ID_CONVERT_A, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CONVERT_A,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CONVERT_B, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CONVERT_B,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CALL_F_A, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_CALL_FAR,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_IMMO, ITE_EO_IMMSL, ITE_NOOP }
  },
{ X86IM_IO_ID_WAIT, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_WAIT,
  1,
  ITE_ENC(_ITE_ENC_F32), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSHF, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSHF,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POPF, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POPF,
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SAHF, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_SAHF,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LAHF, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_LAHF,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_IO_IRAD, ITE_EO_MMFD, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_IO_IRAD, ITE_EO_MMFD, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_MM_AC, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MMFD, ITE_IO_IRAS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_MM_AC, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_DB),
  { ITE_EO_MMFD, ITE_IO_IRAS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_MOVS_, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_MOVS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CMPSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_CMPS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE|_ITE_PFX_REPN) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CMPSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_CMPS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE|_ITE_PFX_REPN) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_TEST_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_TEST_AC_IM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_TEST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_STOSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_STOS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_STOSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_STOS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LODSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_LODS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LODSX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_LODS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SCASX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_SCAS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE|_ITE_PFX_REPN) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SCASX, X86IM_IO_SGR_GPI_STRING, X86IM_IO_IMN_SCAS_,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_REPE|_ITE_PFX_REPN) | ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_WB|_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_AC_IM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  1,
  ITE_ENC(_ITE_ENC_FIM), ITE_REX(_ITE_REX_W|_ITE_REX_B) | ITE_BIT(_ITE_BIT_W3),  
  { ITE_EO_ORAD, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_C0, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_C1, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_RET_N_IM, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_RET_NEAR,
  1,
  ITE_ENC(_ITE_ENC_F64), 0,
  { ITE_EO_IMMO16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_RET_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_RET_NEAR,
  1,
  ITE_ENC(_ITE_ENC_F64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LES, X86IM_IO_SGR_GPI_SEGM, X86IM_IO_IMN_LES,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_MRRGD, ITE_EO_MMFP, ITE_NOOP }
  },
{ X86IM_IO_ID_LDS, X86IM_IO_SGR_GPI_SEGM, X86IM_IO_IMN_LDS,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_MRRGD, ITE_EO_MMFP, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_C6, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_C7, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_ENTER, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_ENTER,
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_IMM2O24, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LEAVE, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_LEAVE,
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_RET_F_IM, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_RET_FAR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_IMMO16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_RET_F, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_RET_FAR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INT3, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_INT3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INTN, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_INT,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INTO, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_INTO,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IRET, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_IRET,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W) | ITE_BIT(_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_D0, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_D1, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_D2, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_D3, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_AAM, X86IM_IO_SGR_GPI_DARITH, X86IM_IO_IMN_AAM,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_AAD, X86IM_IO_SGR_GPI_DARITH, X86IM_IO_IMN_AAD,
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_XLAT, X86IM_IO_SGR_GPI_MISC, X86IM_IO_IMN_XLAT,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_FPU, X86IM_FPU_D8, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_FPU, X86IM_FPU_D9, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_FPU, X86IM_FPU_DA, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_FPU, X86IM_FPU_DB, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_FPU, X86IM_FPU_DC, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_FPU, X86IM_FPU_DD, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_FPU, X86IM_FPU_DE, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_FPU, X86IM_FPU_DF, 0, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_LOOPNE, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_LOOPNE, 
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LOOPE, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_LOOPE,
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_LOOP, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_LOOP,
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_JCXZ, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCXZ, 
  1,
  ITE_ENC(_ITE_ENC_D64), ITE_BIT(_ITE_BIT_NZ),
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IN_IM, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_IN, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_IMMO8, ITE_IO_IRAD, ITE_NOOP }
  },
{ X86IM_IO_ID_IN_IM, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_IN, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_IMMO8, ITE_IO_IRAD, ITE_NOOP }
  },
{ X86IM_IO_ID_OUT_IM, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_OUT,  
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_IMMO8, ITE_IO_IRAS, ITE_NOOP }
  },
{ X86IM_IO_ID_OUT_IM, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_OUT,  
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_IMMO8, ITE_IO_IRAS, ITE_NOOP }
  },
{ X86IM_IO_ID_CALL_N_R, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_CALL,
  1,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), 0,
  { ITE_EO_IMMO, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_JMP_N_R, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JMP, 
  1,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), 0,
  { ITE_EO_IMMO, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_JMP_F_A, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JMP_FAR,  
  1,
  ITE_ENC(_ITE_ENC_I64), 0,
  { ITE_EO_IMMO, ITE_EO_IMMSL, ITE_NOOP }
  },
{ X86IM_IO_ID_JMP_N_R_S, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JMP_SHORT,
  1,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_IMMO8, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_IN_RG, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_IN,  
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_IO_RD16S, ITE_NOOP }
  },
{ X86IM_IO_ID_IN_RG, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_IN,  
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_IRAD, ITE_IO_RD16S, ITE_NOOP }
  },
{ X86IM_IO_ID_OUT_RG, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_OUT, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_RD16S, ITE_IO_IRAS, ITE_NOOP }
  },
{ X86IM_IO_ID_OUT_RG, X86IM_IO_SGR_GPI_IO, X86IM_IO_IMN_OUT, 
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_BIT(_ITE_BIT_WB),
  { ITE_IO_RD16S, ITE_IO_IRAS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_HLT, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_HLT,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CMC, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_CMC,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_F6, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_F7, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CLC, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_CLC,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_STC, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_STC,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CLI, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_CLI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_STI, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_STI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CLD, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_CLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_STD, X86IM_IO_SGR_GPI_FCTL, X86IM_IO_IMN_STD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_FE, ITE_NOIMN, 0, 0, ITE_BIT(_ITE_BIT_WB), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_FF, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_2byte_prefix66[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVUPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVUPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVUPD_XMMR2_XMMR1, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVUPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVLPD_XMMRG_MM64, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVLPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_MMS64, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVLPD_MM64_XMMRG, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVLPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD64, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_UNPCKLPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_UNPACK, X86IM_IO_IMN_UNPCKLPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_UNPCKHPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_UNPACK, X86IM_IO_IMN_UNPCKHPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVHPD_XMMRG_MM64, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVHPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_MMS64, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVHPD_MM64_XMMRG, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVHPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD64, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVAPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVAPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVAPD_XMMR2_XMMR1, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVAPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTPI2PD_XMMR1_MMXR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTPI2PD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVNTPD_MM_XMMRG, X86IM_IO_SGR_SSE2_MISC, X86IM_IO_IMN_MOVNTPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD128, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTTPD2PI_MMXR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTTPD2PI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTPD2PI_MMXR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTPD2PI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_UCOMISD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_COMP, X86IM_IO_IMN_UCOMISD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_COMISD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_COMP, X86IM_IO_IMN_COMISD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVMSKPD_R1_XMMR2, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVMSKPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MRRMXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_SQRTPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_SQRTPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_ANDPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_LOGIC, X86IM_IO_IMN_ANDPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ANDNPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_LOGIC, X86IM_IO_IMN_ANDNPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ORPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_LOGIC, X86IM_IO_IMN_ORPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XORPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_LOGIC, X86IM_IO_IMN_XORPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADDPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_ADDPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MULPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_MULPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTPD2PS_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTPD2PS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTPS2DQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_SSEEXT, X86IM_IO_IMN_CVTPS2DQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUBPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_SUBPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MINPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_MINPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_DIVPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_DIVPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MAXPD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_MAXPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKLBW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKLBW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKLBW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PACKSSWB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PACKSSWB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPGTB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PCMPGT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPGTB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PCMPGT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPGTB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PCMPGT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PACKUSWB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PACKUSWB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKHBW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKHBW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKHBW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PACKSSDW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PACKSSDW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKLQDQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKLQDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKHQDQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PUNPCKHQDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVD_XMMRG_RG, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVDQA_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVDQA,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSHUFD_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSHUFD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  },
{ X86IM_GRP, ITE_GRP_0F_71, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_0F_72, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_0F_73, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PCMPEQB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PCMPEQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPEQB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PCMPEQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPEQB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PCMPEQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_HADDPD_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_HADDPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_HSUBPD_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_HSUBPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVD_RG_XMMRG, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVDQA_XMMR2_XMMR1, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVDQA,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CMPPD_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE2_COMP, X86IM_IO_IMN_CMPPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PINSRW_XMMR1_R2_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PINSRW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_SRGMM16, ITE_EO_IMMM8 }
  },
{ X86IM_IO_ID_PEXTRW_R1_XMMR2_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PEXTRW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MRRMXMS, ITE_EO_IMMM8 }
  },
{ X86IM_IO_ID_SHUFPD_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE2_SHUFFLE, X86IM_IO_IMN_SHUFPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  },
{ X86IM_GRP, ITE_GRP_0F_C7, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_ADDSUBPD_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_ADDSUBPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRLW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRLD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRLQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULLW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMULLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVQ_XMMR2_XMMR1, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM64, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_PMOVMSKB_R1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMOVMSKB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MRRMXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBUSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUBUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBUSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUBUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMINUB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMINUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PAND_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PAND,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDUSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADDUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDUSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADDUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMAXUB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMAXUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PANDN_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PANDN,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PAVGB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PAVGB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRAW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRAW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRAD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSRAD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PAVGW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PAVGW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULHUW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMULHUW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  }, 
{ X86IM_IO_ID_PMULHW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMULHW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTTPD2DQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTTPD2DQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVNTDQ_MM_XMMRG, X86IM_IO_SGR_SSE2_MISC, X86IM_IO_IMN_MOVNTDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD128, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUBS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUBS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMINSW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMINSW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_POR_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_POR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADDS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDSB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADDS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMAXSW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMAXSW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PXOR_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PXOR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },  
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSLLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSLLD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSLLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSLLQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSLLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULUDQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMULUDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMADDWD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMADDWD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },  
{ X86IM_IO_ID_PSADBW_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSADBW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MASKMOVDQU_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MISC, X86IM_IO_IMN_MASKMOVDQU,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_MRRMXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUBQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDB_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_2byte_prefixF2[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVSD_XMMR2_XMMR1, X86IM_IO_SGR_SSE2_TRANSF, X86IM_IO_IMN_MOVSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM64, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVDDUP_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_MOVDDUP,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CVTSI2SD_XMMR1_R2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTSI2SD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CVTTSD2SI_R1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTTSD2SI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTSD2SI_R1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTSD2SI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_SQRTSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_SQRTSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_ADDSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_ADDSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_MULSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_MULSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTSD2SS_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTSD2SS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_SUBSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_SUBSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_MINSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_MINSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_DIVSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_DIVSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_MAXSD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_ARITH, X86IM_IO_IMN_MAXSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSHUFLW_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSHUFLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_HADDPS_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_HADDPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_HSUBPS_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_HSUBPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CMPSD_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE2_COMP, X86IM_IO_IMN_CMPSD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_EO_IMMM8 }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, 0, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_ADDSUBPS_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_ADDSUBPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVDQ2Q_MMXR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVDQ2Q,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MRRMXMS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CVTPD2DQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTPD2DQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_LDDQU_XMMRG_MM, X86IM_IO_GR_SSE3, X86IM_IO_IMN_LDDQU,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F2) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_MMS128, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_2byte_prefixF3[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVSS_XMMR2_XMMR1, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM32, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVSLDUP_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_MOVSLDUP,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },

{ X86IM_IO_ID_MOVSHDUP_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_MOVSHDUP,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CVTSI2SS_XMMR1_R2, X86IM_IO_SGR_SSE_CONV, X86IM_IO_IMN_CVTSI2SS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CVTTSS2SI_R1_XMMR2, X86IM_IO_SGR_SSE_CONV, X86IM_IO_IMN_CVTTSS2SI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTSS2SI_R1_XMMR2, X86IM_IO_SGR_SSE_CONV, X86IM_IO_IMN_CVTSS2SI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_SQRTSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_SQRTSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  }, 
{ X86IM_IO_ID_RSQRTSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_RSQRTSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_RCPSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_RCPSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_ADDSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_ADDSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_MULSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_MULSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTSS2SD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTSS2SD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTTPS2DQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_SSEEXT, X86IM_IO_IMN_CVTTPS2DQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUBSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_SUBSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_MINSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_MINSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_DIVSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_DIVSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_MAXSS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_MAXSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVDQU_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVDQU,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSHUFHW_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSHUFHW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVQ_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVDQU_XMMR2_XMMR1, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVDQU,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CMPSS_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE_COMP, X86IM_IO_IMN_CMPSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_EO_IMMM8 }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_0F_C7, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVQ2DQ_XMMR1_MMXR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_MOVQ2DQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_MRRMMXS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CVTDQ2PD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTDQ2PD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_2byte_noprefix[]=
{
{ X86IM_GRP, ITE_GRP_0F_00, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_0F_01, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_LAR_RG_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_LAR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_LSL_RG_MM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_LSL, 
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_SYSCALL, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SYSCALL,
  2,
  ITE_ENC(_ITE_ENC_O64), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
},
{ X86IM_IO_ID_CLTS, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_CLTS, 
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SYSRET, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SYSRET,
  2,
  ITE_ENC(_ITE_ENC_O64), ITE_BIT(_ITE_BIT_NZ),
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_INVD, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_INVD, 
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_WBINVD, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_WBINVD,  
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_UD2, X86IM_IO_SGR_GPI_MISC, X86IM_IO_IMN_UD2,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVUPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVUPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVUPS_XMMR2_XMMR1, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVUPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVHLPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVHLPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),    
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVLPS_MM64_XMMRG, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVLPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD64, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_UNPCKLPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_UNPACK, X86IM_IO_IMN_UNPCKLPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_UNPCKHPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_UNPACK, X86IM_IO_IMN_UNPCKHPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVLHPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVLHPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),   
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVHPS_MM64_XMMRG, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVHPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD64, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_GRP, ITE_GRP_0F_18, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOV_RG_CRX, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_F64), ITE_REX(_ITE_REX_W|_ITE_REX_R) | ITE_BIT(_ITE_BIT_DB),
  { ITE_EO_MRRMD, ITE_EO_MRCX, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_RG_DRX, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV, 
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_F64), ITE_REX(_ITE_REX_W|_ITE_REX_R) | ITE_BIT(_ITE_BIT_DB),
  { ITE_EO_MRRMD, ITE_EO_MRDX, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_CRX_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV, 
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_F64), ITE_REX(_ITE_REX_W|_ITE_REX_R) | ITE_BIT(_ITE_BIT_DB),
  { ITE_EO_MRCX, ITE_EO_MRRMS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOV_DRX_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOV, 
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_F64), ITE_REX(_ITE_REX_W|_ITE_REX_R) | ITE_BIT(_ITE_BIT_DB),
  { ITE_EO_MRDX, ITE_EO_MRRMS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVAPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVAPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVAPS_XMMR2_XMMR1, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVAPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_XMDRGMM, ITE_EO_MRRMXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTPI2PS_XMMR1_MMXR2, X86IM_IO_SGR_SSE_CONV, X86IM_IO_IMN_CVTPI2PS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVNTPS_MM_XMMRG, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_MOVNTPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD128, ITE_EO_MRRGXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTTPS2PI_MMXR1_XMMR2, X86IM_IO_SGR_SSE_CONV, X86IM_IO_IMN_CVTTPS2PI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTPS2PI_MMXR1_XMMR2, X86IM_IO_SGR_SSE_CONV, X86IM_IO_IMN_CVTPS2PI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_UCOMISS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_COMP, X86IM_IO_IMN_UCOMISS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_COMISS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_COMP, X86IM_IO_IMN_COMISS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_WRMSR, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_WRMSR,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_RDTSC, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_RDTSC,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_RDMSR, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_RDMSR,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_RDPMC, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_RDPMC,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SYSENTER, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SYSENTER,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_SYSEXIT, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_SYSEXIT,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_CMOVCC_RG_MM, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMOVCC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_MRRGD, ITE_EO_SRGMM }
  },
{ X86IM_IO_ID_MOVMSKPS_R1_XMMR2, X86IM_IO_SGR_SSE_TRANSF, X86IM_IO_IMN_MOVMSKPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MRRMXMS, ITE_NOOP }
  },
{ X86IM_IO_ID_SQRTPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_SQRTPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_RSQRTPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_RSQRTPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_RCPPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_RCPPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ANDPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_LOGIC, X86IM_IO_IMN_ANDPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ANDNPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_LOGIC, X86IM_IO_IMN_ANDNPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ORPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_LOGIC, X86IM_IO_IMN_ORPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_XORPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_LOGIC, X86IM_IO_IMN_XORPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_ADDPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_ADDPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MULPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_MULPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTPS2PD_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_CONV, X86IM_IO_IMN_CVTPS2PD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM64, ITE_NOOP }
  },
{ X86IM_IO_ID_CVTDQ2PS_XMMR1_XMMR2, X86IM_IO_SGR_SSE2_SSEEXT, X86IM_IO_IMN_CVTDQ2PS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SUBPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_SUBPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MINPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_MINPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_DIVPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_DIVPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MAXPS_XMMR1_XMMR2, X86IM_IO_SGR_SSE_ARITH, X86IM_IO_IMN_MAXPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKLBW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PUNPCKL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKLBW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PUNPCKL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKLBW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PUNPCKL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM32, ITE_NOOP }
  },
{ X86IM_IO_ID_PACKSSWB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PACKSSWB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) |ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPGTB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_COMP, X86IM_IO_IMN_PCMPGT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPGTB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_COMP, X86IM_IO_IMN_PCMPGT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPGTB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_COMP, X86IM_IO_IMN_PCMPGT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PACKUSWB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PACKUSWB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKHBW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PUNPCKH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKHBW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PUNPCKH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUNPCKHBW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PUNPCKH,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PACKSSDW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_CONV, X86IM_IO_IMN_PACKSSDW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_66), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_66), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVD_MMXRG_MM, X86IM_IO_SGR_MMX_TRANSF, X86IM_IO_IMN_MOVD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVQ_MMXR1_MMXR2, X86IM_IO_SGR_MMX_TRANSF, X86IM_IO_IMN_MOVQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSHUFW_MMXR1_MMXR2_IMM8, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PSHUFW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_EO_IMMM8 }
  },
{ X86IM_GRP, ITE_GRP_0F_71, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_0F_72, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_0F_73, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PCMPEQB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_COMP, X86IM_IO_IMN_PCMPEQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPEQB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_COMP, X86IM_IO_IMN_PCMPEQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PCMPEQB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_COMP, X86IM_IO_IMN_PCMPEQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_EMMS, X86IM_IO_SGR_MMX_STATE, X86IM_IO_IMN_EMMS,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVD_MM_MMXRG, X86IM_IO_SGR_MMX_TRANSF, X86IM_IO_IMN_MOVD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGMXS, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVQ_MMXR2_MMXR1, X86IM_IO_SGR_MMX_TRANSF, X86IM_IO_IMN_MOVQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MXDRGMM, ITE_EO_MRRGMXS, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_JCC_N, X86IM_IO_SGR_GPI_BRANCH, X86IM_IO_IMN_JCC,
  2,
  ITE_ENC(_ITE_ENC_D64|_ITE_ENC_NS), ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_IMMO, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_SETCC_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_SETCC,
  2,
  ITE_ENC(_ITE_ENC_F8), ITE_REX(_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NC),
  { ITE_EO_SOTTTN, ITE_EO_DRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PUSH_SR2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  2,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_ORS3, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_SR2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP,
  2,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_ORS3, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_CPUID, X86IM_IO_SGR_GPI_MISC, X86IM_IO_IMN_CPUID,
  2,
  ITE_ENC(_ITE_ENC_F32), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BT_MM_RG, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_SHLD_MM_RG_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_EO_IMMM8 }
  },
{ X86IM_IO_ID_SHLD_MM_RG_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_IO_RC8S }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PUSH_SR2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_PUSH,
  2,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_ORS3, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_POP_SR2, X86IM_IO_SGR_GPI_STACK, X86IM_IO_IMN_POP,
  2,
  ITE_ENC(_ITE_ENC_D64), 0,
  { ITE_EO_ORS3, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_RSM, X86IM_IO_SGR_GPI_SYSTEM, X86IM_IO_IMN_RSM,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BTS_MM_RG, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BTS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_SHRD_MM_RG_IM, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHRD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_EO_IMMM8 }
  },
{ X86IM_IO_ID_SHRD_MM_RG_CL, X86IM_IO_SGR_GPI_SHIFT, X86IM_IO_IMN_SHRD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_IO_RC8S }
  },
{ X86IM_GRP, ITE_GRP_0F_AE, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_IMUL_RG_MM, X86IM_IO_SGR_GPI_BARITH, X86IM_IO_IMN_IMUL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_CMPXCHG_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMPXCHG,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_CMPXCHG_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_CMPXCHG,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_LSS, X86IM_IO_SGR_GPI_SEGM, X86IM_IO_IMN_LSS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MMFP, ITE_NOOP }
  },
{ X86IM_IO_ID_BTR_MM_RG, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BTR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_LFS, X86IM_IO_SGR_GPI_SEGM, X86IM_IO_IMN_LFS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MMFP, ITE_NOOP }
  },
{ X86IM_IO_ID_LGS, X86IM_IO_SGR_GPI_SEGM, X86IM_IO_IMN_LGS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MMFP, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVZX_RG_MM8, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOVZX,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_SRG8MM8, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVZX_RG_MM16, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOVZX,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_MRRGD, ITE_EO_SRG16MM16, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_GRP, ITE_GRP_0F_BA, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_BTC_MM_RG, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BTC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_BSF_RG_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BSF,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_BSR_RG_MM, X86IM_IO_SGR_GPI_BB, X86IM_IO_IMN_BSR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_SRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVSX_RG_MM8, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOVSX,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_SRG8MM8, ITE_NOOP }
  },
{ X86IM_IO_ID_MOVSX_RG_MM16, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_MOVSX,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_MRRGD, ITE_EO_SRG16MM16, ITE_NOOP }
  },
{ X86IM_IO_ID_XADD_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_XADD_MM_RG, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_XADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_PFX(_ITE_PFX_LOCK) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_WB),
  { ITE_EO_DRGMM, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_CMPPS_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE_COMP, X86IM_IO_IMN_CMPPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  },
{ X86IM_IO_ID_MOVNTI_MM_RG, X86IM_IO_SGR_SSE2_MISC, X86IM_IO_IMN_MOVNTI,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD, ITE_EO_MRRGS, ITE_NOOP }
  },
{ X86IM_IO_ID_PINSRW_MMXR1_R2_IMM8, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PINSRW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_SRGMM16, ITE_EO_IMMM8 }
  },
{ X86IM_IO_ID_PEXTRW_R1_MMXR2_IMM8, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PEXTRW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MRRMMXS, ITE_EO_IMMM8 }
  },
{ X86IM_IO_ID_SHUFPS_XMMR1_XMMR2_IMM8, X86IM_IO_SGR_SSE_SHUFFLE, X86IM_IO_IMN_SHUFPS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  },
{ X86IM_GRP, ITE_GRP_0F_C7, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_BSWAP, X86IM_IO_SGR_GPI_TRANSF, X86IM_IO_IMN_BSWAP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_B),
  { ITE_EO_MRRMD, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSRLW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRLD_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRLQ_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDQ_MMXR1_MMXR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PADDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULLW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PMULLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PMOVMSKB_R1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PMOVMSKB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGD, ITE_EO_MRRMMXS, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBUSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PSUBUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBUSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PSUBUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMINUB_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PMINUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PAND_MMXR1_MMXR2, X86IM_IO_SGR_MMX_LOGIC, X86IM_IO_IMN_PAND,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDUSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PADDUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDUSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PADDUS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMAXUB_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PMAXUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PANDN_MMXR1_MMXR2, X86IM_IO_SGR_MMX_LOGIC, X86IM_IO_IMN_PANDN,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PAVGB_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PAVGB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRAW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRAW, 
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSRAD_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSRAD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PAVGW_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PAVGW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULHUW_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PMULHUW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULHW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PMULHW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_66|_ITE_SOMI_MP_F2|_ITE_SOMI_MP_F3), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_MOVNTQ_MM_MMXRG, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_MOVNTQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD64, ITE_EO_MRRGMXS, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PSUBS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PSUBS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMINSW_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PMINSW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_POR_MMXR1_MMXR2, X86IM_IO_SGR_MMX_LOGIC, X86IM_IO_IMN_POR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PADDS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDSB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PADDS,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMAXSW_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PMAXSW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PXOR_MMXR1_MMXR2, X86IM_IO_SGR_MMX_LOGIC, X86IM_IO_IMN_PXOR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, ITE_SOMI(_ITE_SOMI_MP_F2), { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PSLLW_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSLLW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSLLD_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSLLD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSLLQ_MMXR1_MMXR2, X86IM_IO_SGR_MMX_SHIFT, X86IM_IO_IMN_PSLLQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULUDQ_MMXR1_MMXR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PMULUDQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMADDWD_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PMADDWD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSADBW_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MMXEXT, X86IM_IO_IMN_PSADBW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_MASKMOVQ_MMXR1_MMXR2, X86IM_IO_SGR_SSE_MISC, X86IM_IO_IMN_MASKMOVQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MRRMMXS, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PSUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PSUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PSUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSUBQ_MMXR1_MMXR2, X86IM_IO_SGR_SSE2_MMXEXT, X86IM_IO_IMN_PSUBQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PADDB_MMXR1_MMXR2, X86IM_IO_SGR_MMX_PARITH, X86IM_IO_IMN_PADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_3byte_38_prefix66[]=
{
{ X86IM_IO_ID_PSHUFB_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSHUFB,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHADDW_XMMR1_XMMR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHADD,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHADDW_XMMR1_XMMR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHADD,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHADDSW_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHADDSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMADDUBSW_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PMADDUBSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHSUBW_XMMR1_XMMR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHSUB,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHSUBW_XMMR1_XMMR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHSUB,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHSUBSW_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHSUBSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSIGNB_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSIGN,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSIGNB_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSIGN,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSIGNB_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSIGN,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULHRSW_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PMULHRSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PABSB_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PABS,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PABSB_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PABS,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PABSB_XMMR1_XMMR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PABS,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_3byte_38_prefixF2[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_3byte_38_prefixF3[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_3byte_38_noprefix[]=
{
{ X86IM_IO_ID_PSHUFB_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSHUFB,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHADDW_MMXR1_MMXR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHADD,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHADDW_MMXR1_MMXR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHADD,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHADDSW_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHADDSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMADDUBSW_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PMADDUBSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHSUBW_MMXR1_MMXR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHSUB,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHSUBW_MMXR1_MMXR2-2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHSUB,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PHSUBSW_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PHSUBSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSIGNB_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSIGN,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSIGNB_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSIGN,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSIGNB_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PSIGN,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULHRSW_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PMULHRSW,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PABSB_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PABS,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PABSB_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PABS,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PABSB_MMXR1_MMXR2, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PABS,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B) | ITE_BIT(_ITE_BIT_NZ|_ITE_BIT_GG),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_3byte_3A_prefix66[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PALIGNR_XMMR1_XMMR2_IMM8, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PALIGNR,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGXMD, ITE_EO_XMSRGMM, ITE_EO_IMMM8 }
  }
};

x86im_itbl_entry itbl_3byte_3A_prefixF2[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_3byte_3A_prefixF3[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_3byte_3A_noprefix[]=
{
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_PALIGNR_MMXR1_MMXR2_IMM8, X86IM_IO_GR_SSE3, X86IM_IO_IMN_PALIGNR,
  3,
  ITE_ENC(_ITE_ENC_DEF), ITE_SOMI(_ITE_SOMI_BASE|_ITE_SOMI_MP_66) | ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_EO_IMMM8 }
  }
};

x86im_itbl_entry itbl_fpu_C0_FF_D8[]=
{ 
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_ST0_STX, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_00_BF_D8[]=
{
{ X86IM_IO_ID_FADD_MM32FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_MM32FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_MM32FP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_MM32FP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_MM32FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_MM32FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_MM32FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_MM32FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_C0_FF_D9[]=
{         
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLD_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FNOP, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNOP,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP1, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP1,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCHS, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCHS,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FABS, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FABS,
  2, 
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FTST, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FTST,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FXAM, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXAM,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FLD1, X86IM_IO_SGR_FPU_LOADC, X86IM_IO_IMN_FLD1,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDL2T, X86IM_IO_SGR_FPU_LOADC, X86IM_IO_IMN_FLDL2T,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDL2E, X86IM_IO_SGR_FPU_LOADC, X86IM_IO_IMN_FLDL2E,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDPI, X86IM_IO_SGR_FPU_LOADC, X86IM_IO_IMN_FLDPI,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDLG2, X86IM_IO_SGR_FPU_LOADC, X86IM_IO_IMN_FLDLG2,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDLN2, X86IM_IO_SGR_FPU_LOADC, X86IM_IO_IMN_FLDLN2,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDZ, X86IM_IO_SGR_FPU_LOADC, X86IM_IO_IMN_FLDZ,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_F2XM1, X86IM_IO_SGR_FPU_LES, X86IM_IO_IMN_F2XM1,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FYL2X, X86IM_IO_SGR_FPU_LES, X86IM_IO_IMN_FYL2X,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_IO_MRST1, ITE_NOOP }
  },
{ X86IM_IO_ID_FPTAN, X86IM_IO_SGR_FPU_TRIGO, X86IM_IO_IMN_FPTAN,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FPATAN, X86IM_IO_SGR_FPU_TRIGO, X86IM_IO_IMN_FPATAN,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_IO_MRST1, ITE_NOOP }
  },
{ X86IM_IO_ID_FXTRACT, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FXTRACT,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FPREM1, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FPREM1,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST1, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FDECSTP, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FDECSTP,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FINCSTP, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FINCSTP,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FPREM, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FPREM,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST1, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FYL2XP1, X86IM_IO_SGR_FPU_LES, X86IM_IO_IMN_FYL2XP1,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_IO_MRST1, ITE_NOOP }
  },
{ X86IM_IO_ID_FSQRT, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSQRT,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FSINCOS, X86IM_IO_SGR_FPU_TRIGO, X86IM_IO_IMN_FSINCOS,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FRNDINT, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FRNDINT,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FSCALE, X86IM_IO_SGR_FPU_LES, X86IM_IO_IMN_FSCALE,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_IO_MRST1, ITE_NOOP }
  },
{ X86IM_IO_ID_FSIN, X86IM_IO_SGR_FPU_TRIGO, X86IM_IO_IMN_FSIN,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOS, X86IM_IO_SGR_FPU_TRIGO, X86IM_IO_IMN_FCOS,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_NOOP, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_00_BF_D9[]=
{
{ X86IM_IO_ID_FLD_MM32FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FST_MM32FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_MM32FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDENV, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FLDENV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_FPU_ENV, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FLDCW, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FLDCW,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FNSTENV, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNSTENV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_FPU_ENV, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FNSTCW, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNSTCW,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD16, ITE_NOOP, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_C0_FF_DA[]=
{
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FUCOMPP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMPP,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0, ITE_IO_MRST1, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_fpu_00_BF_DA[]=
{
{ X86IM_IO_ID_FIADD_MM32I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIMUL_MM32I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FICOM_MM32I, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FICOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FICOMP_MM32I, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FICOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FISUB_MM32I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FISUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FISUBR_MM32I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FISUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIDIV_MM32I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIDIVR_MM32I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_C0_FF_DB[]=
{         
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNB_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNBE_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNBE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCMOVNU_ST0_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FCMOVNU,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FNCLEX, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNCLEX,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FNINIT, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNINIT,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_NOOP, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMI_ST0_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMI,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_fpu_00_BF_DB[]=
{
{ X86IM_IO_ID_FILD_MM32I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FILD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FISTTP_MM32I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FISTTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIST_MM32I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FIST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD32, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FISTP_MM32I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FISTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD32, ITE_IO_MRST0, ITE_NOOP }
  }, 
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FLD_MM80FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS80, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FSTP_MM80FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD80, ITE_IO_MRST0, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_C0_FF_DC[]=
{         
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADD_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM2_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOM2,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP3, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP3,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_00_BF_DC[]=
{
{ X86IM_IO_ID_FADD_MM64FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FMUL_MM64FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOM_MM64FP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP_MM64FP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUB_MM64FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBR_MM64FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIV_MM64FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVR_MM64FP, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_C0_FF_DD[]=
{         
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FFREE,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH4, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FXCH4,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FST_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
 },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_STX, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOM_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMP_STX, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_fpu_00_BF_DD[]=
{
{ X86IM_IO_ID_FLD_MM64FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FISTTP_MM64I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FISTTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FST_MM64FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP_MM64FP, X86IM_IO_SGR_FPU_TRANSF_FP, X86IM_IO_IMN_FSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FRSTOR, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FRSTOR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_FPU_ST, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FNSAVE, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNSAVE,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_FPU_ST, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FNSTSW_MB2, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNSTSW,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MMD16, ITE_NOOP, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_C0_FF_DE[]=
{ 
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FADDP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FADDP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FMULP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FMULP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMP5, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FCOMP5,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_IO_MRST0, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FCOMPP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMPP,
  2,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0, ITE_IO_MRST1, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FSUBP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FSUBP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVRP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVRP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
{ X86IM_IO_ID_FDIVP_STX_ST0, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FDIVP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0S, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_00_BF_DE[]=
{
{ X86IM_IO_ID_FIADD_MM16I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIADD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIMUL_MM16I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIMUL,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FICOM_MM16I, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FICOM,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FICOMP_MM16I, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FICOMP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FISUB_MM16I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FISUB,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FISUBR_MM16I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FISUBR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIDIV_MM16I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIDIV,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIDIVR_MM16I, X86IM_IO_SGR_FPU_ARITH, X86IM_IO_IMN_FIDIVR,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_IO_MRST0, ITE_NOOP }
  },
};

x86im_itbl_entry itbl_fpu_C0_FF_DF[]=
{         
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FFREEP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FFREEP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXS, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FXCH7, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FXCH7,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP8, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP8,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FSTP9, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FSTP9,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_EO_MRSTXD, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FNSTSW_AX, X86IM_IO_SGR_FPU_CTRL, X86IM_IO_IMN_FNSTSW,
  2,
  ITE_ENC(_ITE_ENC_F16), 0,
  { ITE_IO_IRAD, ITE_NOOP, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FUCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FUCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ X86IM_IO_ID_FCOMIP, X86IM_IO_SGR_FPU_COCL, X86IM_IO_IMN_FCOMIP,
  1,
  ITE_ENC(_ITE_ENC_DEF), 0,  
  { ITE_IO_MRST0D, ITE_EO_MRSTXS, ITE_NOOP }
  },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
{ ITE_INV, ITE_NOGRP, ITE_NOIMN, 0, 0, 0, { ITE_NOOP, ITE_NOOP, ITE_NOOP } },
};

x86im_itbl_entry itbl_fpu_00_BF_DF[]=
{
{ X86IM_IO_ID_FILD_MM16I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FILD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS16, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FISTTP_MM16I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FISTTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FIST_MM16I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FIST,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FISTP_MM16I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FISTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD16, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FBLD, X86IM_IO_SGR_FPU_TRANSF_PD, X86IM_IO_IMN_FBLD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD80, ITE_NOOP, ITE_NOOP }
  },
{ X86IM_IO_ID_FILD_MM64I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FILD,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMS64, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FBSTP, X86IM_IO_SGR_FPU_TRANSF_PD, X86IM_IO_IMN_FBSTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD80, ITE_IO_MRST0, ITE_NOOP }
  },
{ X86IM_IO_ID_FISTP_MM64I, X86IM_IO_SGR_FPU_TRANSF_I, X86IM_IO_IMN_FISTP,
  1,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),  
  { ITE_EO_MMD64, ITE_IO_MRST0, ITE_NOOP }
  },
};

x86im_itbl_entry *cmd_fpu_tbl_00_BF[]=
{
    itbl_fpu_00_BF_D8, 
    itbl_fpu_00_BF_D9, 
    itbl_fpu_00_BF_DA, 
    itbl_fpu_00_BF_DB, 
    itbl_fpu_00_BF_DC, 
    itbl_fpu_00_BF_DD, 
    itbl_fpu_00_BF_DE, 
    itbl_fpu_00_BF_DF  
};

x86im_itbl_entry *cmd_fpu_tbl_C0_FF[]=
{
    itbl_fpu_C0_FF_D8,
    itbl_fpu_C0_FF_D9,
    itbl_fpu_C0_FF_DA,
    itbl_fpu_C0_FF_DB,
    itbl_fpu_C0_FF_DC,
    itbl_fpu_C0_FF_DD,
    itbl_fpu_C0_FF_DE,
    itbl_fpu_C0_FF_DF 
};

x86im_itbl_entry *itbl_1byte_grps[]=
{   
    itbl_1byte_grp1_op_80,
    itbl_1byte_grp1_op_81,
    itbl_1byte_grp1_op_82,
    itbl_1byte_grp1_op_83,
    itbl_1byte_grp1A_op_8F,
    itbl_1byte_grp2_op_C0,
    itbl_1byte_grp2_op_C1,
    itbl_1byte_grp11_op_C6,
    itbl_1byte_grp11_op_C7,
    itbl_1byte_grp2_op_D0,
    itbl_1byte_grp2_op_D1,
    itbl_1byte_grp2_op_D2,
    itbl_1byte_grp2_op_D3,
    itbl_1byte_grp3_op_F6,
    itbl_1byte_grp3_op_F7,
    itbl_1byte_grp4_op_FE,
    itbl_1byte_grp5_op_FF
};

x86im_itbl_entry *itbl_2byte_grps[]=
{
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp6_op_0F_00,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp7_op_0F_01,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp16_op_0F_18,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp12_op_0F_71_pfx66,
    itbl_grp12_op_0F_71,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp13_op_0F_72_pfx66,
    itbl_grp13_op_0F_72,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp14_op_0F_73_pfx66,
    itbl_grp14_op_0F_73,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp15_op_0F_AE,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp8_op_0F_BA,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp_invalid,
    itbl_grp9_op_0F_C7
};

x86im_itbl_entry *itbl_2byte[]=
{
    itbl_2byte_prefixF3,
    itbl_2byte_prefixF2,
    itbl_2byte_prefix66,
    itbl_2byte_noprefix
};

x86im_itbl_entry *itbl_3byte_38[]=
{
    itbl_3byte_38_prefixF3,
    itbl_3byte_38_prefixF2,
    itbl_3byte_38_prefix66,
    itbl_3byte_38_noprefix
};

x86im_itbl_entry *itbl_3byte_3A[]=
{
    itbl_3byte_3A_prefixF3,
    itbl_3byte_3A_prefixF2,
    itbl_3byte_3A_prefix66,
    itbl_3byte_3A_noprefix
};

x86im_itbl_entry itbl_AMD3DNow[]=
{
{ X86IM_IO_ID_PI2FW_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PI2FW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PI2FD_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PI2FD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PF2IW_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PF2IW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PF2ID_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PF2ID,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFNACC_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFNACC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFPNACC_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFPNACC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFCMPGE_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFCMPGE,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFMIN_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFMIN,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFRCP_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFRCP,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFRSQRT_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFRSQRT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFSUB_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFSUB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFADD_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFADD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFCMPGT_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFCMPGT,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFMAX_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFMAX,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFRCPIT1_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFRCPIT1,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFRSQIT1_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFRSQIT1,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFSUBR_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFSUBR,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFACC_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFACC,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFCMPEQ_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFCMPEQ,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFMUL_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFMUL,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PFRCPIT2_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PFRCPIT2,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_R|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PMULHRW_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PMULHRW,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PSWAPD_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PSWAPD,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  },
{ X86IM_IO_ID_PAVGUSB_MMXR1_MMXR2, X86IM_IO_GR_3DNOW, X86IM_IO_IMN_PAVGUSB,
  2,
  ITE_ENC(_ITE_ENC_DEF), ITE_REX(_ITE_REX_W|_ITE_REX_X|_ITE_REX_B),
  { ITE_EO_MRRGMXD, ITE_EO_MXSRGMM, ITE_NOOP }
  }
};

#endif // __X86IM_ITBL_H__
