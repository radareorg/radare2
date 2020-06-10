

/* AM33 relocations.  */
#define R_MN10300_NONE		0	/* No reloc.  */
#define R_MN10300_32		1	/* Direct 32 bit.  */
#define R_MN10300_16		2	/* Direct 16 bit.  */
#define R_MN10300_8		3	/* Direct 8 bit.  */
#define R_MN10300_PCREL32	4	/* PC-relative 32-bit.  */
#define R_MN10300_PCREL16	5	/* PC-relative 16-bit signed.  */
#define R_MN10300_PCREL8	6	/* PC-relative 8-bit signed.  */
#define R_MN10300_GNU_VTINHERIT	7	/* Ancient C++ vtable garbage... */
#define R_MN10300_GNU_VTENTRY	8	/* ... collection annotation.  */
#define R_MN10300_24		9	/* Direct 24 bit.  */
#define R_MN10300_GOTPC32	10	/* 32-bit PCrel offset to GOT.  */
#define R_MN10300_GOTPC16	11	/* 16-bit PCrel offset to GOT.  */
#define R_MN10300_GOTOFF32	12	/* 32-bit offset from GOT.  */
#define R_MN10300_GOTOFF24	13	/* 24-bit offset from GOT.  */
#define R_MN10300_GOTOFF16	14	/* 16-bit offset from GOT.  */
#define R_MN10300_PLT32		15	/* 32-bit PCrel to PLT entry.  */
#define R_MN10300_PLT16		16	/* 16-bit PCrel to PLT entry.  */
#define R_MN10300_GOT32		17	/* 32-bit offset to GOT entry.  */
#define R_MN10300_GOT24		18	/* 24-bit offset to GOT entry.  */
#define R_MN10300_GOT16		19	/* 16-bit offset to GOT entry.  */
#define R_MN10300_COPY		20	/* Copy symbol at runtime.  */
#define R_MN10300_GLOB_DAT	21	/* Create GOT entry.  */
#define R_MN10300_JMP_SLOT	22	/* Create PLT entry.  */
#define R_MN10300_RELATIVE	23	/* Adjust by program base.  */
#define R_MN10300_TLS_GD	24	/* 32-bit offset for global dynamic.  */
#define R_MN10300_TLS_LD	25	/* 32-bit offset for local dynamic.  */
#define R_MN10300_TLS_LDO	26	/* Module-relative offset.  */
#define R_MN10300_TLS_GOTIE	27	/* GOT offset for static TLS block
					   offset.  */
#define R_MN10300_TLS_IE	28	/* GOT address for static TLS block
					   offset.  */
#define R_MN10300_TLS_LE	29	/* Offset relative to static TLS
					   block.  */
#define R_MN10300_TLS_DTPMOD	30	/* ID of module containing symbol.  */
#define R_MN10300_TLS_DTPOFF	31	/* Offset in module TLS block.  */
#define R_MN10300_TLS_TPOFF	32	/* Offset in static TLS block.  */
#define R_MN10300_SYM_DIFF	33	/* Adjustment for next reloc as needed
					   by linker relaxation.  */
#define R_MN10300_ALIGN		34	/* Alignment requirement for linker
					   relaxation.  */
#define R_MN10300_NUM		35

