/* SUN SPARC specific definitions.  */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_SPARC_REGISTER	13	/* Global register reserved to app. */

/* Values for Elf64_Ehdr.e_flags.  */

#define EF_SPARCV9_MM		3
#define EF_SPARCV9_TSO		0
#define EF_SPARCV9_PSO		1
#define EF_SPARCV9_RMO		2
#define EF_SPARC_LEDATA		0x800000 /* little endian data */
#define EF_SPARC_EXT_MASK	0xFFFF00
#define EF_SPARC_32PLUS		0x000100 /* generic V8+ features */
#define EF_SPARC_SUN_US1	0x000200 /* Sun UltraSPARC1 extensions */
#define EF_SPARC_HAL_R1		0x000400 /* HAL R1 extensions */
#define EF_SPARC_SUN_US3	0x000800 /* Sun UltraSPARCIII extensions */

/* SPARC relocs.  */

#define R_SPARC_NONE		0	/* No reloc */
#define R_SPARC_8		1	/* Direct 8 bit */
#define R_SPARC_16		2	/* Direct 16 bit */
#define R_SPARC_32		3	/* Direct 32 bit */
#define R_SPARC_DISP8		4	/* PC relative 8 bit */
#define R_SPARC_DISP16		5	/* PC relative 16 bit */
#define R_SPARC_DISP32		6	/* PC relative 32 bit */
#define R_SPARC_WDISP30		7	/* PC relative 30 bit shifted */
#define R_SPARC_WDISP22		8	/* PC relative 22 bit shifted */
#define R_SPARC_HI22		9	/* High 22 bit */
#define R_SPARC_22		10	/* Direct 22 bit */
#define R_SPARC_13		11	/* Direct 13 bit */
#define R_SPARC_LO10		12	/* Truncated 10 bit */
#define R_SPARC_GOT10		13	/* Truncated 10 bit GOT entry */
#define R_SPARC_GOT13		14	/* 13 bit GOT entry */
#define R_SPARC_GOT22		15	/* 22 bit GOT entry shifted */
#define R_SPARC_PC10		16	/* PC relative 10 bit truncated */
#define R_SPARC_PC22		17	/* PC relative 22 bit shifted */
#define R_SPARC_WPLT30		18	/* 30 bit PC relative PLT address */
#define R_SPARC_COPY		19	/* Copy symbol at runtime */
#define R_SPARC_GLOB_DAT	20	/* Create GOT entry */
#define R_SPARC_JMP_SLOT	21	/* Create PLT entry */
#define R_SPARC_RELATIVE	22	/* Adjust by program base */
#define R_SPARC_UA32		23	/* Direct 32 bit unaligned */

/* Additional Sparc64 relocs.  */

#define R_SPARC_PLT32		24	/* Direct 32 bit ref to PLT entry */
#define R_SPARC_HIPLT22		25	/* High 22 bit PLT entry */
#define R_SPARC_LOPLT10		26	/* Truncated 10 bit PLT entry */
#define R_SPARC_PCPLT32		27	/* PC rel 32 bit ref to PLT entry */
#define R_SPARC_PCPLT22		28	/* PC rel high 22 bit PLT entry */
#define R_SPARC_PCPLT10		29	/* PC rel trunc 10 bit PLT entry */
#define R_SPARC_10		30	/* Direct 10 bit */
#define R_SPARC_11		31	/* Direct 11 bit */
#define R_SPARC_64		32	/* Direct 64 bit */
#define R_SPARC_OLO10		33	/* 10bit with secondary 13bit addend */
#define R_SPARC_HH22		34	/* Top 22 bits of direct 64 bit */
#define R_SPARC_HM10		35	/* High middle 10 bits of ... */
#define R_SPARC_LM22		36	/* Low middle 22 bits of ... */
#define R_SPARC_PC_HH22		37	/* Top 22 bits of pc rel 64 bit */
#define R_SPARC_PC_HM10		38	/* High middle 10 bit of ... */
#define R_SPARC_PC_LM22		39	/* Low miggle 22 bits of ... */
#define R_SPARC_WDISP16		40	/* PC relative 16 bit shifted */
#define R_SPARC_WDISP19		41	/* PC relative 19 bit shifted */
#define R_SPARC_GLOB_JMP	42	/* was part of v9 ABI but was removed */
#define R_SPARC_7		43	/* Direct 7 bit */
#define R_SPARC_5		44	/* Direct 5 bit */
#define R_SPARC_6		45	/* Direct 6 bit */
#define R_SPARC_DISP64		46	/* PC relative 64 bit */
#define R_SPARC_PLT64		47	/* Direct 64 bit ref to PLT entry */
#define R_SPARC_HIX22		48	/* High 22 bit complemented */
#define R_SPARC_LOX10		49	/* Truncated 11 bit complemented */
#define R_SPARC_H44		50	/* Direct high 12 of 44 bit */
#define R_SPARC_M44		51	/* Direct mid 22 of 44 bit */
#define R_SPARC_L44		52	/* Direct low 10 of 44 bit */
#define R_SPARC_REGISTER	53	/* Global register usage */
#define R_SPARC_UA64		54	/* Direct 64 bit unaligned */
#define R_SPARC_UA16		55	/* Direct 16 bit unaligned */
#define R_SPARC_TLS_GD_HI22	56
#define R_SPARC_TLS_GD_LO10	57
#define R_SPARC_TLS_GD_ADD	58
#define R_SPARC_TLS_GD_CALL	59
#define R_SPARC_TLS_LDM_HI22	60
#define R_SPARC_TLS_LDM_LO10	61
#define R_SPARC_TLS_LDM_ADD	62
#define R_SPARC_TLS_LDM_CALL	63
#define R_SPARC_TLS_LDO_HIX22	64
#define R_SPARC_TLS_LDO_LOX10	65
#define R_SPARC_TLS_LDO_ADD	66
#define R_SPARC_TLS_IE_HI22	67
#define R_SPARC_TLS_IE_LO10	68
#define R_SPARC_TLS_IE_LD	69
#define R_SPARC_TLS_IE_LDX	70
#define R_SPARC_TLS_IE_ADD	71
#define R_SPARC_TLS_LE_HIX22	72
#define R_SPARC_TLS_LE_LOX10	73
#define R_SPARC_TLS_DTPMOD32	74
#define R_SPARC_TLS_DTPMOD64	75
#define R_SPARC_TLS_DTPOFF32	76
#define R_SPARC_TLS_DTPOFF64	77
#define R_SPARC_TLS_TPOFF32	78
#define R_SPARC_TLS_TPOFF64	79
#define R_SPARC_GOTDATA_HIX22	80
#define R_SPARC_GOTDATA_LOX10	81
#define R_SPARC_GOTDATA_OP_HIX22	82
#define R_SPARC_GOTDATA_OP_LOX10	83
#define R_SPARC_GOTDATA_OP	84
#define R_SPARC_H34		85
#define R_SPARC_SIZE32		86
#define R_SPARC_SIZE64		87
#define R_SPARC_WDISP10		88
#define R_SPARC_JMP_IREL	248
#define R_SPARC_IRELATIVE	249
#define R_SPARC_GNU_VTINHERIT	250
#define R_SPARC_GNU_VTENTRY	251
#define R_SPARC_REV32		252
/* Keep this the last entry.  */
#define R_SPARC_NUM		253

/* For Sparc64, legal values for d_tag of Elf64_Dyn.  */

#define DT_SPARC_REGISTER	0x70000001
#define DT_SPARC_NUM		2

