/* M32R relocs.  */
#define R_M32R_NONE		0	/* No reloc. */
#define R_M32R_16		1	/* Direct 16 bit. */
#define R_M32R_32		2	/* Direct 32 bit. */
#define R_M32R_24		3	/* Direct 24 bit. */
#define R_M32R_10_PCREL		4	/* PC relative 10 bit shifted. */
#define R_M32R_18_PCREL		5	/* PC relative 18 bit shifted. */
#define R_M32R_26_PCREL		6	/* PC relative 26 bit shifted. */
#define R_M32R_HI16_ULO		7	/* High 16 bit with unsigned low. */
#define R_M32R_HI16_SLO		8	/* High 16 bit with signed low. */
#define R_M32R_LO16		9	/* Low 16 bit. */
#define R_M32R_SDA16		10	/* 16 bit offset in SDA. */
#define R_M32R_GNU_VTINHERIT	11
#define R_M32R_GNU_VTENTRY	12
/* M32R relocs use SHT_RELA.  */
#define R_M32R_16_RELA		33	/* Direct 16 bit. */
#define R_M32R_32_RELA		34	/* Direct 32 bit. */
#define R_M32R_24_RELA		35	/* Direct 24 bit. */
#define R_M32R_10_PCREL_RELA	36	/* PC relative 10 bit shifted. */
#define R_M32R_18_PCREL_RELA	37	/* PC relative 18 bit shifted. */
#define R_M32R_26_PCREL_RELA	38	/* PC relative 26 bit shifted. */
#define R_M32R_HI16_ULO_RELA	39	/* High 16 bit with unsigned low */
#define R_M32R_HI16_SLO_RELA	40	/* High 16 bit with signed low */
#define R_M32R_LO16_RELA	41	/* Low 16 bit */
#define R_M32R_SDA16_RELA	42	/* 16 bit offset in SDA */
#define R_M32R_RELA_GNU_VTINHERIT	43
#define R_M32R_RELA_GNU_VTENTRY	44
#define R_M32R_REL32		45	/* PC relative 32 bit.  */

#define R_M32R_GOT24		48	/* 24 bit GOT entry */
#define R_M32R_26_PLTREL	49	/* 26 bit PC relative to PLT shifted */
#define R_M32R_COPY		50	/* Copy symbol at runtime */
#define R_M32R_GLOB_DAT		51	/* Create GOT entry */
#define R_M32R_JMP_SLOT		52	/* Create PLT entry */
#define R_M32R_RELATIVE		53	/* Adjust by program base */
#define R_M32R_GOTOFF		54	/* 24 bit offset to GOT */
#define R_M32R_GOTPC24		55	/* 24 bit PC relative offset to GOT */
#define R_M32R_GOT16_HI_ULO	56	/* High 16 bit GOT entry with unsigned
					   low */
#define R_M32R_GOT16_HI_SLO	57	/* High 16 bit GOT entry with signed
					   low */
#define R_M32R_GOT16_LO		58	/* Low 16 bit GOT entry */
#define R_M32R_GOTPC_HI_ULO	59	/* High 16 bit PC relative offset to
					   GOT with unsigned low */
#define R_M32R_GOTPC_HI_SLO	60	/* High 16 bit PC relative offset to
					   GOT with signed low */
#define R_M32R_GOTPC_LO		61	/* Low 16 bit PC relative offset to
					   GOT */
#define R_M32R_GOTOFF_HI_ULO	62	/* High 16 bit offset to GOT
					   with unsigned low */
#define R_M32R_GOTOFF_HI_SLO	63	/* High 16 bit offset to GOT
					   with signed low */
#define R_M32R_GOTOFF_LO	64	/* Low 16 bit offset to GOT */
#define R_M32R_NUM		256	/* Keep this the last entry. */

