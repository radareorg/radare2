

/* TILEPro relocations.  */
#define R_TILEPRO_NONE		0	/* No reloc */
#define R_TILEPRO_32		1	/* Direct 32 bit */
#define R_TILEPRO_16		2	/* Direct 16 bit */
#define R_TILEPRO_8		3	/* Direct 8 bit */
#define R_TILEPRO_32_PCREL	4	/* PC relative 32 bit */
#define R_TILEPRO_16_PCREL	5	/* PC relative 16 bit */
#define R_TILEPRO_8_PCREL	6	/* PC relative 8 bit */
#define R_TILEPRO_LO16		7	/* Low 16 bit */
#define R_TILEPRO_HI16		8	/* High 16 bit */
#define R_TILEPRO_HA16		9	/* High 16 bit, adjusted */
#define R_TILEPRO_COPY		10	/* Copy relocation */
#define R_TILEPRO_GLOB_DAT	11	/* Create GOT entry */
#define R_TILEPRO_JMP_SLOT	12	/* Create PLT entry */
#define R_TILEPRO_RELATIVE	13	/* Adjust by program base */
#define R_TILEPRO_BROFF_X1	14	/* X1 pipe branch offset */
#define R_TILEPRO_JOFFLONG_X1	15	/* X1 pipe jump offset */
#define R_TILEPRO_JOFFLONG_X1_PLT 16	/* X1 pipe jump offset to PLT */
#define R_TILEPRO_IMM8_X0	17	/* X0 pipe 8-bit */
#define R_TILEPRO_IMM8_Y0	18	/* Y0 pipe 8-bit */
#define R_TILEPRO_IMM8_X1	19	/* X1 pipe 8-bit */
#define R_TILEPRO_IMM8_Y1	20	/* Y1 pipe 8-bit */
#define R_TILEPRO_MT_IMM15_X1	21	/* X1 pipe mtspr */
#define R_TILEPRO_MF_IMM15_X1	22	/* X1 pipe mfspr */
#define R_TILEPRO_IMM16_X0	23	/* X0 pipe 16-bit */
#define R_TILEPRO_IMM16_X1	24	/* X1 pipe 16-bit */
#define R_TILEPRO_IMM16_X0_LO	25	/* X0 pipe low 16-bit */
#define R_TILEPRO_IMM16_X1_LO	26	/* X1 pipe low 16-bit */
#define R_TILEPRO_IMM16_X0_HI	27	/* X0 pipe high 16-bit */
#define R_TILEPRO_IMM16_X1_HI	28	/* X1 pipe high 16-bit */
#define R_TILEPRO_IMM16_X0_HA	29	/* X0 pipe high 16-bit, adjusted */
#define R_TILEPRO_IMM16_X1_HA	30	/* X1 pipe high 16-bit, adjusted */
#define R_TILEPRO_IMM16_X0_PCREL 31	/* X0 pipe PC relative 16 bit */
#define R_TILEPRO_IMM16_X1_PCREL 32	/* X1 pipe PC relative 16 bit */
#define R_TILEPRO_IMM16_X0_LO_PCREL 33	/* X0 pipe PC relative low 16 bit */
#define R_TILEPRO_IMM16_X1_LO_PCREL 34	/* X1 pipe PC relative low 16 bit */
#define R_TILEPRO_IMM16_X0_HI_PCREL 35	/* X0 pipe PC relative high 16 bit */
#define R_TILEPRO_IMM16_X1_HI_PCREL 36	/* X1 pipe PC relative high 16 bit */
#define R_TILEPRO_IMM16_X0_HA_PCREL 37	/* X0 pipe PC relative ha() 16 bit */
#define R_TILEPRO_IMM16_X1_HA_PCREL 38	/* X1 pipe PC relative ha() 16 bit */
#define R_TILEPRO_IMM16_X0_GOT	39	/* X0 pipe 16-bit GOT offset */
#define R_TILEPRO_IMM16_X1_GOT	40	/* X1 pipe 16-bit GOT offset */
#define R_TILEPRO_IMM16_X0_GOT_LO 41	/* X0 pipe low 16-bit GOT offset */
#define R_TILEPRO_IMM16_X1_GOT_LO 42	/* X1 pipe low 16-bit GOT offset */
#define R_TILEPRO_IMM16_X0_GOT_HI 43	/* X0 pipe high 16-bit GOT offset */
#define R_TILEPRO_IMM16_X1_GOT_HI 44	/* X1 pipe high 16-bit GOT offset */
#define R_TILEPRO_IMM16_X0_GOT_HA 45	/* X0 pipe ha() 16-bit GOT offset */
#define R_TILEPRO_IMM16_X1_GOT_HA 46	/* X1 pipe ha() 16-bit GOT offset */
#define R_TILEPRO_MMSTART_X0	47	/* X0 pipe mm "start" */
#define R_TILEPRO_MMEND_X0	48	/* X0 pipe mm "end" */
#define R_TILEPRO_MMSTART_X1	49	/* X1 pipe mm "start" */
#define R_TILEPRO_MMEND_X1	50	/* X1 pipe mm "end" */
#define R_TILEPRO_SHAMT_X0	51	/* X0 pipe shift amount */
#define R_TILEPRO_SHAMT_X1	52	/* X1 pipe shift amount */
#define R_TILEPRO_SHAMT_Y0	53	/* Y0 pipe shift amount */
#define R_TILEPRO_SHAMT_Y1	54	/* Y1 pipe shift amount */
#define R_TILEPRO_DEST_IMM8_X1	55	/* X1 pipe destination 8-bit */
/* Relocs 56-59 are currently not defined.  */
#define R_TILEPRO_TLS_GD_CALL	60	/* "jal" for TLS GD */
#define R_TILEPRO_IMM8_X0_TLS_GD_ADD 61	/* X0 pipe "addi" for TLS GD */
#define R_TILEPRO_IMM8_X1_TLS_GD_ADD 62	/* X1 pipe "addi" for TLS GD */
#define R_TILEPRO_IMM8_Y0_TLS_GD_ADD 63	/* Y0 pipe "addi" for TLS GD */
#define R_TILEPRO_IMM8_Y1_TLS_GD_ADD 64	/* Y1 pipe "addi" for TLS GD */
#define R_TILEPRO_TLS_IE_LOAD	65	/* "lw_tls" for TLS IE */
#define R_TILEPRO_IMM16_X0_TLS_GD 66	/* X0 pipe 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X1_TLS_GD 67	/* X1 pipe 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X0_TLS_GD_LO 68	/* X0 pipe low 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X1_TLS_GD_LO 69	/* X1 pipe low 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X0_TLS_GD_HI 70	/* X0 pipe high 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X1_TLS_GD_HI 71	/* X1 pipe high 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X0_TLS_GD_HA 72	/* X0 pipe ha() 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X1_TLS_GD_HA 73	/* X1 pipe ha() 16-bit TLS GD offset */
#define R_TILEPRO_IMM16_X0_TLS_IE 74	/* X0 pipe 16-bit TLS IE offset */
#define R_TILEPRO_IMM16_X1_TLS_IE 75	/* X1 pipe 16-bit TLS IE offset */
#define R_TILEPRO_IMM16_X0_TLS_IE_LO 76	/* X0 pipe low 16-bit TLS IE offset */
#define R_TILEPRO_IMM16_X1_TLS_IE_LO 77	/* X1 pipe low 16-bit TLS IE offset */
#define R_TILEPRO_IMM16_X0_TLS_IE_HI 78	/* X0 pipe high 16-bit TLS IE offset */
#define R_TILEPRO_IMM16_X1_TLS_IE_HI 79	/* X1 pipe high 16-bit TLS IE offset */
#define R_TILEPRO_IMM16_X0_TLS_IE_HA 80	/* X0 pipe ha() 16-bit TLS IE offset */
#define R_TILEPRO_IMM16_X1_TLS_IE_HA 81	/* X1 pipe ha() 16-bit TLS IE offset */
#define R_TILEPRO_TLS_DTPMOD32	82	/* ID of module containing symbol */
#define R_TILEPRO_TLS_DTPOFF32	83	/* Offset in TLS block */
#define R_TILEPRO_TLS_TPOFF32	84	/* Offset in static TLS block */
#define R_TILEPRO_IMM16_X0_TLS_LE 85	/* X0 pipe 16-bit TLS LE offset */
#define R_TILEPRO_IMM16_X1_TLS_LE 86	/* X1 pipe 16-bit TLS LE offset */
#define R_TILEPRO_IMM16_X0_TLS_LE_LO 87	/* X0 pipe low 16-bit TLS LE offset */
#define R_TILEPRO_IMM16_X1_TLS_LE_LO 88	/* X1 pipe low 16-bit TLS LE offset */
#define R_TILEPRO_IMM16_X0_TLS_LE_HI 89	/* X0 pipe high 16-bit TLS LE offset */
#define R_TILEPRO_IMM16_X1_TLS_LE_HI 90	/* X1 pipe high 16-bit TLS LE offset */
#define R_TILEPRO_IMM16_X0_TLS_LE_HA 91	/* X0 pipe ha() 16-bit TLS LE offset */
#define R_TILEPRO_IMM16_X1_TLS_LE_HA 92	/* X1 pipe ha() 16-bit TLS LE offset */

#define R_TILEPRO_GNU_VTINHERIT	128	/* GNU C++ vtable hierarchy */
#define R_TILEPRO_GNU_VTENTRY	129	/* GNU C++ vtable member usage */

#define R_TILEPRO_NUM		130


/* TILE-Gx relocations.  */
#define R_TILEGX_NONE		0	/* No reloc */
#define R_TILEGX_64		1	/* Direct 64 bit */
#define R_TILEGX_32		2	/* Direct 32 bit */
#define R_TILEGX_16		3	/* Direct 16 bit */
#define R_TILEGX_8		4	/* Direct 8 bit */
#define R_TILEGX_64_PCREL	5	/* PC relative 64 bit */
#define R_TILEGX_32_PCREL	6	/* PC relative 32 bit */
#define R_TILEGX_16_PCREL	7	/* PC relative 16 bit */
#define R_TILEGX_8_PCREL	8	/* PC relative 8 bit */
#define R_TILEGX_HW0		9	/* hword 0 16-bit */
#define R_TILEGX_HW1		10	/* hword 1 16-bit */
#define R_TILEGX_HW2		11	/* hword 2 16-bit */
#define R_TILEGX_HW3		12	/* hword 3 16-bit */
#define R_TILEGX_HW0_LAST	13	/* last hword 0 16-bit */
#define R_TILEGX_HW1_LAST	14	/* last hword 1 16-bit */
#define R_TILEGX_HW2_LAST	15	/* last hword 2 16-bit */
#define R_TILEGX_COPY		16	/* Copy relocation */
#define R_TILEGX_GLOB_DAT	17	/* Create GOT entry */
#define R_TILEGX_JMP_SLOT	18	/* Create PLT entry */
#define R_TILEGX_RELATIVE	19	/* Adjust by program base */
#define R_TILEGX_BROFF_X1	20	/* X1 pipe branch offset */
#define R_TILEGX_JUMPOFF_X1	21	/* X1 pipe jump offset */
#define R_TILEGX_JUMPOFF_X1_PLT	22	/* X1 pipe jump offset to PLT */
#define R_TILEGX_IMM8_X0	23	/* X0 pipe 8-bit */
#define R_TILEGX_IMM8_Y0	24	/* Y0 pipe 8-bit */
#define R_TILEGX_IMM8_X1	25	/* X1 pipe 8-bit */
#define R_TILEGX_IMM8_Y1	26	/* Y1 pipe 8-bit */
#define R_TILEGX_DEST_IMM8_X1	27	/* X1 pipe destination 8-bit */
#define R_TILEGX_MT_IMM14_X1	28	/* X1 pipe mtspr */
#define R_TILEGX_MF_IMM14_X1	29	/* X1 pipe mfspr */
#define R_TILEGX_MMSTART_X0	30	/* X0 pipe mm "start" */
#define R_TILEGX_MMEND_X0	31	/* X0 pipe mm "end" */
#define R_TILEGX_SHAMT_X0	32	/* X0 pipe shift amount */
#define R_TILEGX_SHAMT_X1	33	/* X1 pipe shift amount */
#define R_TILEGX_SHAMT_Y0	34	/* Y0 pipe shift amount */
#define R_TILEGX_SHAMT_Y1	35	/* Y1 pipe shift amount */
#define R_TILEGX_IMM16_X0_HW0	36	/* X0 pipe hword 0 */
#define R_TILEGX_IMM16_X1_HW0	37	/* X1 pipe hword 0 */
#define R_TILEGX_IMM16_X0_HW1	38	/* X0 pipe hword 1 */
#define R_TILEGX_IMM16_X1_HW1	39	/* X1 pipe hword 1 */
#define R_TILEGX_IMM16_X0_HW2	40	/* X0 pipe hword 2 */
#define R_TILEGX_IMM16_X1_HW2	41	/* X1 pipe hword 2 */
#define R_TILEGX_IMM16_X0_HW3	42	/* X0 pipe hword 3 */
#define R_TILEGX_IMM16_X1_HW3	43	/* X1 pipe hword 3 */
#define R_TILEGX_IMM16_X0_HW0_LAST 44	/* X0 pipe last hword 0 */
#define R_TILEGX_IMM16_X1_HW0_LAST 45	/* X1 pipe last hword 0 */
#define R_TILEGX_IMM16_X0_HW1_LAST 46	/* X0 pipe last hword 1 */
#define R_TILEGX_IMM16_X1_HW1_LAST 47	/* X1 pipe last hword 1 */
#define R_TILEGX_IMM16_X0_HW2_LAST 48	/* X0 pipe last hword 2 */
#define R_TILEGX_IMM16_X1_HW2_LAST 49	/* X1 pipe last hword 2 */
#define R_TILEGX_IMM16_X0_HW0_PCREL 50	/* X0 pipe PC relative hword 0 */
#define R_TILEGX_IMM16_X1_HW0_PCREL 51	/* X1 pipe PC relative hword 0 */
#define R_TILEGX_IMM16_X0_HW1_PCREL 52	/* X0 pipe PC relative hword 1 */
#define R_TILEGX_IMM16_X1_HW1_PCREL 53	/* X1 pipe PC relative hword 1 */
#define R_TILEGX_IMM16_X0_HW2_PCREL 54	/* X0 pipe PC relative hword 2 */
#define R_TILEGX_IMM16_X1_HW2_PCREL 55	/* X1 pipe PC relative hword 2 */
#define R_TILEGX_IMM16_X0_HW3_PCREL 56	/* X0 pipe PC relative hword 3 */
#define R_TILEGX_IMM16_X1_HW3_PCREL 57	/* X1 pipe PC relative hword 3 */
#define R_TILEGX_IMM16_X0_HW0_LAST_PCREL 58 /* X0 pipe PC-rel last hword 0 */
#define R_TILEGX_IMM16_X1_HW0_LAST_PCREL 59 /* X1 pipe PC-rel last hword 0 */
#define R_TILEGX_IMM16_X0_HW1_LAST_PCREL 60 /* X0 pipe PC-rel last hword 1 */
#define R_TILEGX_IMM16_X1_HW1_LAST_PCREL 61 /* X1 pipe PC-rel last hword 1 */
#define R_TILEGX_IMM16_X0_HW2_LAST_PCREL 62 /* X0 pipe PC-rel last hword 2 */
#define R_TILEGX_IMM16_X1_HW2_LAST_PCREL 63 /* X1 pipe PC-rel last hword 2 */
#define R_TILEGX_IMM16_X0_HW0_GOT 64	/* X0 pipe hword 0 GOT offset */
#define R_TILEGX_IMM16_X1_HW0_GOT 65	/* X1 pipe hword 0 GOT offset */
#define R_TILEGX_IMM16_X0_HW0_PLT_PCREL 66 /* X0 pipe PC-rel PLT hword 0 */
#define R_TILEGX_IMM16_X1_HW0_PLT_PCREL 67 /* X1 pipe PC-rel PLT hword 0 */
#define R_TILEGX_IMM16_X0_HW1_PLT_PCREL 68 /* X0 pipe PC-rel PLT hword 1 */
#define R_TILEGX_IMM16_X1_HW1_PLT_PCREL 69 /* X1 pipe PC-rel PLT hword 1 */
#define R_TILEGX_IMM16_X0_HW2_PLT_PCREL 70 /* X0 pipe PC-rel PLT hword 2 */
#define R_TILEGX_IMM16_X1_HW2_PLT_PCREL 71 /* X1 pipe PC-rel PLT hword 2 */
#define R_TILEGX_IMM16_X0_HW0_LAST_GOT 72 /* X0 pipe last hword 0 GOT offset */
#define R_TILEGX_IMM16_X1_HW0_LAST_GOT 73 /* X1 pipe last hword 0 GOT offset */
#define R_TILEGX_IMM16_X0_HW1_LAST_GOT 74 /* X0 pipe last hword 1 GOT offset */
#define R_TILEGX_IMM16_X1_HW1_LAST_GOT 75 /* X1 pipe last hword 1 GOT offset */
#define R_TILEGX_IMM16_X0_HW3_PLT_PCREL 76 /* X0 pipe PC-rel PLT hword 3 */
#define R_TILEGX_IMM16_X1_HW3_PLT_PCREL 77 /* X1 pipe PC-rel PLT hword 3 */
#define R_TILEGX_IMM16_X0_HW0_TLS_GD 78	/* X0 pipe hword 0 TLS GD offset */
#define R_TILEGX_IMM16_X1_HW0_TLS_GD 79	/* X1 pipe hword 0 TLS GD offset */
#define R_TILEGX_IMM16_X0_HW0_TLS_LE 80	/* X0 pipe hword 0 TLS LE offset */
#define R_TILEGX_IMM16_X1_HW0_TLS_LE 81	/* X1 pipe hword 0 TLS LE offset */
#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_LE 82 /* X0 pipe last hword 0 LE off */
#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_LE 83 /* X1 pipe last hword 0 LE off */
#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_LE 84 /* X0 pipe last hword 1 LE off */
#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_LE 85 /* X1 pipe last hword 1 LE off */
#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_GD 86 /* X0 pipe last hword 0 GD off */
#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_GD 87 /* X1 pipe last hword 0 GD off */
#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_GD 88 /* X0 pipe last hword 1 GD off */
#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_GD 89 /* X1 pipe last hword 1 GD off */
/* Relocs 90-91 are currently not defined.  */
#define R_TILEGX_IMM16_X0_HW0_TLS_IE 92	/* X0 pipe hword 0 TLS IE offset */
#define R_TILEGX_IMM16_X1_HW0_TLS_IE 93	/* X1 pipe hword 0 TLS IE offset */
#define R_TILEGX_IMM16_X0_HW0_LAST_PLT_PCREL 94 /* X0 pipe PC-rel PLT last hword 0 */
#define R_TILEGX_IMM16_X1_HW0_LAST_PLT_PCREL 95 /* X1 pipe PC-rel PLT last hword 0 */
#define R_TILEGX_IMM16_X0_HW1_LAST_PLT_PCREL 96 /* X0 pipe PC-rel PLT last hword 1 */
#define R_TILEGX_IMM16_X1_HW1_LAST_PLT_PCREL 97 /* X1 pipe PC-rel PLT last hword 1 */
#define R_TILEGX_IMM16_X0_HW2_LAST_PLT_PCREL 98 /* X0 pipe PC-rel PLT last hword 2 */
#define R_TILEGX_IMM16_X1_HW2_LAST_PLT_PCREL 99 /* X1 pipe PC-rel PLT last hword 2 */
#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_IE 100 /* X0 pipe last hword 0 IE off */
#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_IE 101 /* X1 pipe last hword 0 IE off */
#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_IE 102 /* X0 pipe last hword 1 IE off */
#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_IE 103 /* X1 pipe last hword 1 IE off */
/* Relocs 104-105 are currently not defined.  */
#define R_TILEGX_TLS_DTPMOD64	106	/* 64-bit ID of symbol's module */
#define R_TILEGX_TLS_DTPOFF64	107	/* 64-bit offset in TLS block */
#define R_TILEGX_TLS_TPOFF64	108	/* 64-bit offset in static TLS block */
#define R_TILEGX_TLS_DTPMOD32	109	/* 32-bit ID of symbol's module */
#define R_TILEGX_TLS_DTPOFF32	110	/* 32-bit offset in TLS block */
#define R_TILEGX_TLS_TPOFF32	111	/* 32-bit offset in static TLS block */
#define R_TILEGX_TLS_GD_CALL	112	/* "jal" for TLS GD */
#define R_TILEGX_IMM8_X0_TLS_GD_ADD 113	/* X0 pipe "addi" for TLS GD */
#define R_TILEGX_IMM8_X1_TLS_GD_ADD 114	/* X1 pipe "addi" for TLS GD */
#define R_TILEGX_IMM8_Y0_TLS_GD_ADD 115	/* Y0 pipe "addi" for TLS GD */
#define R_TILEGX_IMM8_Y1_TLS_GD_ADD 116	/* Y1 pipe "addi" for TLS GD */
#define R_TILEGX_TLS_IE_LOAD	117	/* "ld_tls" for TLS IE */
#define R_TILEGX_IMM8_X0_TLS_ADD 118	/* X0 pipe "addi" for TLS GD/IE */
#define R_TILEGX_IMM8_X1_TLS_ADD 119	/* X1 pipe "addi" for TLS GD/IE */
#define R_TILEGX_IMM8_Y0_TLS_ADD 120	/* Y0 pipe "addi" for TLS GD/IE */
#define R_TILEGX_IMM8_Y1_TLS_ADD 121	/* Y1 pipe "addi" for TLS GD/IE */

#define R_TILEGX_GNU_VTINHERIT	128	/* GNU C++ vtable hierarchy */
#define R_TILEGX_GNU_VTENTRY	129	/* GNU C++ vtable member usage */

#define R_TILEGX_NUM		130


