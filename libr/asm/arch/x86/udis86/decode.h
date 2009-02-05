#ifndef UD_DECODE_H
#define UD_DECODE_H

#define MAX_INSN_LENGTH 15

/* register classes */
#define T_NONE  0
#define T_GPR   1
#define T_MMX   2
#define T_CRG   3
#define T_DBG   4
#define T_SEG   5
#define T_XMM   6

/* itab prefix bits */
#define P_none          ( 0 )
#define P_c1            ( 1 << 0 )
#define P_C1(n)         ( ( n >> 0 ) & 1 )
#define P_rexb          ( 1 << 1 )
#define P_REXB(n)       ( ( n >> 1 ) & 1 )
#define P_depM          ( 1 << 2 )
#define P_DEPM(n)       ( ( n >> 2 ) & 1 )
#define P_c3            ( 1 << 3 )
#define P_C3(n)         ( ( n >> 3 ) & 1 )
#define P_inv64         ( 1 << 4 )
#define P_INV64(n)      ( ( n >> 4 ) & 1 )
#define P_rexw          ( 1 << 5 )
#define P_REXW(n)       ( ( n >> 5 ) & 1 )
#define P_c2            ( 1 << 6 )
#define P_C2(n)         ( ( n >> 6 ) & 1 )
#define P_def64         ( 1 << 7 )
#define P_DEF64(n)      ( ( n >> 7 ) & 1 )
#define P_rexr          ( 1 << 8 )
#define P_REXR(n)       ( ( n >> 8 ) & 1 )
#define P_oso           ( 1 << 9 )
#define P_OSO(n)        ( ( n >> 9 ) & 1 )
#define P_aso           ( 1 << 10 )
#define P_ASO(n)        ( ( n >> 10 ) & 1 )
#define P_rexx          ( 1 << 11 )
#define P_REXX(n)       ( ( n >> 11 ) & 1 )
#define P_ImpAddr       ( 1 << 12 )
#define P_IMPADDR(n)    ( ( n >> 12 ) & 1 )

/* rex prefix bits */
#define REX_W(r)        ( ( 0xF & ( r ) )  >> 3 )
#define REX_R(r)        ( ( 0x7 & ( r ) )  >> 2 )
#define REX_X(r)        ( ( 0x3 & ( r ) )  >> 1 )
#define REX_B(r)        ( ( 0x1 & ( r ) )  >> 0 )
#define REX_PFX_MASK(n) ( ( P_REXW(n) << 3 ) | \
                          ( P_REXR(n) << 2 ) | \
                          ( P_REXX(n) << 1 ) | \
                          ( P_REXB(n) << 0 ) )

/* scable-index-base bits */
#define SIB_S(b)        ( ( b ) >> 6 )
#define SIB_I(b)        ( ( ( b ) >> 3 ) & 7 )
#define SIB_B(b)        ( ( b ) & 7 )

/* modrm bits */
#define MODRM_REG(b)    ( ( ( b ) >> 3 ) & 7 )
#define MODRM_NNN(b)    ( ( ( b ) >> 3 ) & 7 )
#define MODRM_MOD(b)    ( ( ( b ) >> 6 ) & 3 )
#define MODRM_RM(b)     ( ( b ) & 7 )

/* operand type constants -- order is important! */

enum ud_operand_code {
    OP_NONE,

    OP_A,      OP_E,      OP_M,       OP_G,       
    OP_I,

    OP_AL,     OP_CL,     OP_DL,      OP_BL,
    OP_AH,     OP_CH,     OP_DH,      OP_BH,

    OP_ALr8b,  OP_CLr9b,  OP_DLr10b,  OP_BLr11b,
    OP_AHr12b, OP_CHr13b, OP_DHr14b,  OP_BHr15b,

    OP_AX,     OP_CX,     OP_DX,      OP_BX,
    OP_SI,     OP_DI,     OP_SP,      OP_BP,

    OP_rAX,    OP_rCX,    OP_rDX,     OP_rBX,  
    OP_rSP,    OP_rBP,    OP_rSI,     OP_rDI,

    OP_rAXr8,  OP_rCXr9,  OP_rDXr10,  OP_rBXr11,  
    OP_rSPr12, OP_rBPr13, OP_rSIr14,  OP_rDIr15,

    OP_eAX,    OP_eCX,    OP_eDX,     OP_eBX,
    OP_eSP,    OP_eBP,    OP_eSI,     OP_eDI,

    OP_ES,     OP_CS,     OP_SS,      OP_DS,  
    OP_FS,     OP_GS,

    OP_ST0,    OP_ST1,    OP_ST2,     OP_ST3,
    OP_ST4,    OP_ST5,    OP_ST6,     OP_ST7,

    OP_J,      OP_S,      OP_O,          
    OP_I1,     OP_I3, 

    OP_V,      OP_W,      OP_Q,       OP_P, 

    OP_R,      OP_C,  OP_D,       OP_VR,  OP_PR
};


/* operand size constants */

enum ud_operand_size {
    SZ_NA  = 0,
    SZ_Z   = 1,
    SZ_V   = 2,
    SZ_P   = 3,
    SZ_WP  = 4,
    SZ_DP  = 5,
    SZ_MDQ = 6,
    SZ_RDQ = 7,

    /* the following values are used as is,
     * and thus hard-coded. changing them 
     * will break internals 
     */
    SZ_B   = 8,
    SZ_W   = 16,
    SZ_D   = 32,
    SZ_Q   = 64,
    SZ_T   = 80,
};

/* itab entry operand definitions */

#define O_rSPr12  { OP_rSPr12,   SZ_NA    }
#define O_BL      { OP_BL,       SZ_NA    }
#define O_BH      { OP_BH,       SZ_NA    }
#define O_BP      { OP_BP,       SZ_NA    }
#define O_AHr12b  { OP_AHr12b,   SZ_NA    }
#define O_BX      { OP_BX,       SZ_NA    }
#define O_Jz      { OP_J,        SZ_Z     }
#define O_Jv      { OP_J,        SZ_V     }
#define O_Jb      { OP_J,        SZ_B     }
#define O_rSIr14  { OP_rSIr14,   SZ_NA    }
#define O_GS      { OP_GS,       SZ_NA    }
#define O_D       { OP_D,        SZ_NA    }
#define O_rBPr13  { OP_rBPr13,   SZ_NA    }
#define O_Ob      { OP_O,        SZ_B     }
#define O_P       { OP_P,        SZ_NA    }
#define O_Ow      { OP_O,        SZ_W     }
#define O_Ov      { OP_O,        SZ_V     }
#define O_Gw      { OP_G,        SZ_W     }
#define O_Gv      { OP_G,        SZ_V     }
#define O_rDX     { OP_rDX,      SZ_NA    }
#define O_Gx      { OP_G,        SZ_MDQ   }
#define O_Gd      { OP_G,        SZ_D     }
#define O_Gb      { OP_G,        SZ_B     }
#define O_rBXr11  { OP_rBXr11,   SZ_NA    }
#define O_rDI     { OP_rDI,      SZ_NA    }
#define O_rSI     { OP_rSI,      SZ_NA    }
#define O_ALr8b   { OP_ALr8b,    SZ_NA    }
#define O_eDI     { OP_eDI,      SZ_NA    }
#define O_Gz      { OP_G,        SZ_Z     }
#define O_eDX     { OP_eDX,      SZ_NA    }
#define O_DHr14b  { OP_DHr14b,   SZ_NA    }
#define O_rSP     { OP_rSP,      SZ_NA    }
#define O_PR      { OP_PR,       SZ_NA    }
#define O_NONE    { OP_NONE,     SZ_NA    }
#define O_rCX     { OP_rCX,      SZ_NA    }
#define O_jWP     { OP_J,        SZ_WP    }
#define O_rDXr10  { OP_rDXr10,   SZ_NA    }
#define O_Md      { OP_M,        SZ_D     }
#define O_C       { OP_C,        SZ_NA    }
#define O_G       { OP_G,        SZ_NA    }
#define O_Mb      { OP_M,        SZ_B     }
#define O_Mt      { OP_M,        SZ_T     }
#define O_S       { OP_S,        SZ_NA    }
#define O_Mq      { OP_M,        SZ_Q     }
#define O_W       { OP_W,        SZ_NA    }
#define O_ES      { OP_ES,       SZ_NA    }
#define O_rBX     { OP_rBX,      SZ_NA    }
#define O_Ed      { OP_E,        SZ_D     }
#define O_DLr10b  { OP_DLr10b,   SZ_NA    }
#define O_Mw      { OP_M,        SZ_W     }
#define O_Eb      { OP_E,        SZ_B     }
#define O_Ex      { OP_E,        SZ_MDQ   }
#define O_Ez      { OP_E,        SZ_Z     }
#define O_Ew      { OP_E,        SZ_W     }
#define O_Ev      { OP_E,        SZ_V     }
#define O_Ep      { OP_E,        SZ_P     }
#define O_FS      { OP_FS,       SZ_NA    }
#define O_Ms      { OP_M,        SZ_W     }
#define O_rAXr8   { OP_rAXr8,    SZ_NA    }
#define O_eBP     { OP_eBP,      SZ_NA    }
#define O_Isb     { OP_I,        SZ_SB    }
#define O_eBX     { OP_eBX,      SZ_NA    }
#define O_rCXr9   { OP_rCXr9,    SZ_NA    }
#define O_jDP     { OP_J,        SZ_DP    }
#define O_CH      { OP_CH,       SZ_NA    }
#define O_CL      { OP_CL,       SZ_NA    }
#define O_R       { OP_R,        SZ_RDQ   }
#define O_V       { OP_V,        SZ_NA    }
#define O_CS      { OP_CS,       SZ_NA    }
#define O_CHr13b  { OP_CHr13b,   SZ_NA    }
#define O_eCX     { OP_eCX,      SZ_NA    }
#define O_eSP     { OP_eSP,      SZ_NA    }
#define O_SS      { OP_SS,       SZ_NA    }
#define O_SP      { OP_SP,       SZ_NA    }
#define O_BLr11b  { OP_BLr11b,   SZ_NA    }
#define O_SI      { OP_SI,       SZ_NA    }
#define O_eSI     { OP_eSI,      SZ_NA    }
#define O_DL      { OP_DL,       SZ_NA    }
#define O_DH      { OP_DH,       SZ_NA    }
#define O_DI      { OP_DI,       SZ_NA    }
#define O_DX      { OP_DX,       SZ_NA    }
#define O_rBP     { OP_rBP,      SZ_NA    }
#define O_Gvw     { OP_G,        SZ_MDQ   }
#define O_I1      { OP_I1,       SZ_NA    }
#define O_I3      { OP_I3,       SZ_NA    }
#define O_DS      { OP_DS,       SZ_NA    }
#define O_ST4     { OP_ST4,      SZ_NA    }
#define O_ST5     { OP_ST5,      SZ_NA    }
#define O_ST6     { OP_ST6,      SZ_NA    }
#define O_ST7     { OP_ST7,      SZ_NA    }
#define O_ST0     { OP_ST0,      SZ_NA    }
#define O_ST1     { OP_ST1,      SZ_NA    }
#define O_ST2     { OP_ST2,      SZ_NA    }
#define O_ST3     { OP_ST3,      SZ_NA    }
#define O_E       { OP_E,        SZ_NA    }
#define O_AH      { OP_AH,       SZ_NA    }
#define O_M       { OP_M,        SZ_NA    }
#define O_AL      { OP_AL,       SZ_NA    }
#define O_CLr9b   { OP_CLr9b,    SZ_NA    }
#define O_Q       { OP_Q,        SZ_NA    }
#define O_eAX     { OP_eAX,      SZ_NA    }
#define O_VR      { OP_VR,       SZ_NA    }
#define O_AX      { OP_AX,       SZ_NA    }
#define O_rAX     { OP_rAX,      SZ_NA    }
#define O_Iz      { OP_I,        SZ_Z     }
#define O_rDIr15  { OP_rDIr15,   SZ_NA    }
#define O_Iw      { OP_I,        SZ_W     }
#define O_Iv      { OP_I,        SZ_V     }
#define O_Ap      { OP_A,        SZ_P     }
#define O_CX      { OP_CX,       SZ_NA    }
#define O_Ib      { OP_I,        SZ_B     }
#define O_BHr15b  { OP_BHr15b,   SZ_NA    }


/* A single operand of an entry in the instruction table. 
 * (internal use only)
 */
struct ud_itab_entry_operand 
{
  enum ud_operand_code type;
  enum ud_operand_size size;
};


/* A single entry in an instruction table. 
 *(internal use only)
 */
struct ud_itab_entry 
{
  enum ud_mnemonic_code         mnemonic;
  struct ud_itab_entry_operand  operand1;
  struct ud_itab_entry_operand  operand2;
  struct ud_itab_entry_operand  operand3;
  uint32_t                      prefix;
};

extern const char * ud_lookup_mnemonic( enum ud_mnemonic_code c );

#endif /* UD_DECODE_H */

/* vim:cindent
 * vim:expandtab
 * vim:ts=4
 * vim:sw=4
 */
