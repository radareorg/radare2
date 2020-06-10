

/* csky */
#define R_CKCORE_NONE               0	/* no reloc */
#define R_CKCORE_ADDR32             1	/* direct 32 bit (S + A) */
#define R_CKCORE_PCRELIMM8BY4       2	/* disp ((S + A - P) >> 2) & 0xff   */
#define R_CKCORE_PCRELIMM11BY2      3	/* disp ((S + A - P) >> 1) & 0x7ff  */
#define R_CKCORE_PCREL32            5	/* 32-bit rel (S + A - P)           */
#define R_CKCORE_PCRELJSR_IMM11BY2  6	/* disp ((S + A - P) >>1) & 0x7ff   */
#define R_CKCORE_RELATIVE           9	/* 32 bit adjust program base(B + A)*/
#define R_CKCORE_COPY               10	/* 32 bit adjust by program base    */
#define R_CKCORE_GLOB_DAT           11	/* off between got and sym (S)      */
#define R_CKCORE_JUMP_SLOT          12	/* PLT entry (S) */
#define R_CKCORE_GOTOFF             13	/* offset to GOT (S + A - GOT)      */
#define R_CKCORE_GOTPC              14	/* PC offset to GOT (GOT + A - P)   */
#define R_CKCORE_GOT32              15	/* 32 bit GOT entry (G) */
#define R_CKCORE_PLT32              16	/* 32 bit PLT entry (G) */
#define R_CKCORE_ADDRGOT            17	/* GOT entry in GLOB_DAT (GOT + G)  */
#define R_CKCORE_ADDRPLT            18	/* PLT entry in GLOB_DAT (GOT + G)  */
#define R_CKCORE_PCREL_IMM26BY2     19	/* ((S + A - P) >> 1) & 0x3ffffff   */
#define R_CKCORE_PCREL_IMM16BY2     20	/* disp ((S + A - P) >> 1) & 0xffff */
#define R_CKCORE_PCREL_IMM16BY4     21	/* disp ((S + A - P) >> 2) & 0xffff */
#define R_CKCORE_PCREL_IMM10BY2     22	/* disp ((S + A - P) >> 1) & 0x3ff  */
#define R_CKCORE_PCREL_IMM10BY4     23	/* disp ((S + A - P) >> 2) & 0x3ff  */
#define R_CKCORE_ADDR_HI16          24	/* high & low 16 bit ADDR */
                                        /* ((S + A) >> 16) & 0xffff */
#define R_CKCORE_ADDR_LO16          25	/* (S + A) & 0xffff */
#define R_CKCORE_GOTPC_HI16         26	/* high & low 16 bit GOTPC */
                                        /* ((GOT + A - P) >> 16) & 0xffff */
#define R_CKCORE_GOTPC_LO16         27	/* (GOT + A - P) & 0xffff */
#define R_CKCORE_GOTOFF_HI16        28	/* high & low 16 bit GOTOFF */
                                        /* ((S + A - GOT) >> 16) & 0xffff */
#define R_CKCORE_GOTOFF_LO16        29	/* (S + A - GOT) & 0xffff */
#define R_CKCORE_GOT12              30	/* 12 bit disp GOT entry (G) */
#define R_CKCORE_GOT_HI16           31	/* high & low 16 bit GOT */
                                        /* (G >> 16) & 0xffff */
#define R_CKCORE_GOT_LO16           32	/* (G & 0xffff) */
#define R_CKCORE_PLT12              33	/* 12 bit disp PLT entry (G) */
#define R_CKCORE_PLT_HI16           34	/* high & low 16 bit PLT */
                                        /* (G >> 16) & 0xffff */
#define R_CKCORE_PLT_LO16           35	/* G & 0xffff */
#define R_CKCORE_ADDRGOT_HI16       36	/* high & low 16 bit ADDRGOT */
                                        /* (GOT + G * 4) & 0xffff */
#define R_CKCORE_ADDRGOT_LO16       37	/* (GOT + G * 4) & 0xffff */
#define R_CKCORE_ADDRPLT_HI16       38	/* high & low 16 bit ADDRPLT */
                                        /* ((GOT + G * 4) >> 16) & 0xFFFF */
#define R_CKCORE_ADDRPLT_LO16       39	/* (GOT+G*4) & 0xffff */
#define R_CKCORE_PCREL_JSR_IMM26BY2 40	/* disp ((S+A-P) >>1) & x3ffffff */
#define R_CKCORE_TOFFSET_LO16       41	/* (S+A-BTEXT) & 0xffff */
#define R_CKCORE_DOFFSET_LO16       42	/* (S+A-BTEXT) & 0xffff */
#define R_CKCORE_PCREL_IMM18BY2     43	/* disp ((S+A-P) >>1) & 0x3ffff */
#define R_CKCORE_DOFFSET_IMM18      44	/* disp (S+A-BDATA) & 0x3ffff */
#define R_CKCORE_DOFFSET_IMM18BY2   45	/* disp ((S+A-BDATA)>>1) & 0x3ffff */
#define R_CKCORE_DOFFSET_IMM18BY4   46	/* disp ((S+A-BDATA)>>2) & 0x3ffff */
#define R_CKCORE_GOT_IMM18BY4       48	/* disp (G >> 2) */
#define R_CKCORE_PLT_IMM18BY4       49	/* disp (G >> 2) */
#define R_CKCORE_PCREL_IMM7BY4      50	/* disp ((S+A-P) >>2) & 0x7f */
#define R_CKCORE_TLS_LE32           51  /* 32 bit offset to TLS block */
#define R_CKCORE_TLS_IE32           52
#define R_CKCORE_TLS_GD32           53
#define R_CKCORE_TLS_LDM32          54
#define R_CKCORE_TLS_LDO32          55
#define R_CKCORE_TLS_DTPMOD32       56
#define R_CKCORE_TLS_DTPOFF32       57
#define R_CKCORE_TLS_TPOFF32        58
