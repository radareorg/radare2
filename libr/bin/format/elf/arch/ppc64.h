
/* PowerPC64 relocations defined by the ABIs */
#define R_PPC64_NONE		R_PPC_NONE
#define R_PPC64_ADDR32		R_PPC_ADDR32 /* 32bit absolute address */
#define R_PPC64_ADDR24		R_PPC_ADDR24 /* 26bit address, word aligned */
#define R_PPC64_ADDR16		R_PPC_ADDR16 /* 16bit absolute address */
#define R_PPC64_ADDR16_LO	R_PPC_ADDR16_LO	/* lower 16bits of address */
#define R_PPC64_ADDR16_HI	R_PPC_ADDR16_HI	/* high 16bits of address. */
#define R_PPC64_ADDR16_HA	R_PPC_ADDR16_HA /* adjusted high 16bits.  */
#define R_PPC64_ADDR14		R_PPC_ADDR14 /* 16bit address, word aligned */
#define R_PPC64_ADDR14_BRTAKEN	R_PPC_ADDR14_BRTAKEN
#define R_PPC64_ADDR14_BRNTAKEN	R_PPC_ADDR14_BRNTAKEN
#define R_PPC64_REL24		R_PPC_REL24 /* PC-rel. 26 bit, word aligned */
#define R_PPC64_REL14		R_PPC_REL14 /* PC relative 16 bit */
#define R_PPC64_REL14_BRTAKEN	R_PPC_REL14_BRTAKEN
#define R_PPC64_REL14_BRNTAKEN	R_PPC_REL14_BRNTAKEN
#define R_PPC64_GOT16		R_PPC_GOT16
#define R_PPC64_GOT16_LO	R_PPC_GOT16_LO
#define R_PPC64_GOT16_HI	R_PPC_GOT16_HI
#define R_PPC64_GOT16_HA	R_PPC_GOT16_HA

#define R_PPC64_COPY		R_PPC_COPY
#define R_PPC64_GLOB_DAT	R_PPC_GLOB_DAT
#define R_PPC64_JMP_SLOT	R_PPC_JMP_SLOT
#define R_PPC64_RELATIVE	R_PPC_RELATIVE

#define R_PPC64_UADDR32		R_PPC_UADDR32
#define R_PPC64_UADDR16		R_PPC_UADDR16
#define R_PPC64_REL32		R_PPC_REL32
#define R_PPC64_PLT32		R_PPC_PLT32
#define R_PPC64_PLTREL32	R_PPC_PLTREL32
#define R_PPC64_PLT16_LO	R_PPC_PLT16_LO
#define R_PPC64_PLT16_HI	R_PPC_PLT16_HI
#define R_PPC64_PLT16_HA	R_PPC_PLT16_HA

#define R_PPC64_SECTOFF		R_PPC_SECTOFF
#define R_PPC64_SECTOFF_LO	R_PPC_SECTOFF_LO
#define R_PPC64_SECTOFF_HI	R_PPC_SECTOFF_HI
#define R_PPC64_SECTOFF_HA	R_PPC_SECTOFF_HA
#define R_PPC64_ADDR30		37 /* word30 (S + A - P) >> 2 */
#define R_PPC64_ADDR64		38 /* doubleword64 S + A */
#define R_PPC64_ADDR16_HIGHER	39 /* half16 #higher(S + A) */
#define R_PPC64_ADDR16_HIGHERA	40 /* half16 #highera(S + A) */
#define R_PPC64_ADDR16_HIGHEST	41 /* half16 #highest(S + A) */
#define R_PPC64_ADDR16_HIGHESTA	42 /* half16 #highesta(S + A) */
#define R_PPC64_UADDR64		43 /* doubleword64 S + A */
#define R_PPC64_REL64		44 /* doubleword64 S + A - P */
#define R_PPC64_PLT64		45 /* doubleword64 L + A */
#define R_PPC64_PLTREL64	46 /* doubleword64 L + A - P */
#define R_PPC64_TOC16		47 /* half16* S + A - .TOC */
#define R_PPC64_TOC16_LO	48 /* half16 #lo(S + A - .TOC.) */
#define R_PPC64_TOC16_HI	49 /* half16 #hi(S + A - .TOC.) */
#define R_PPC64_TOC16_HA	50 /* half16 #ha(S + A - .TOC.) */
#define R_PPC64_TOC		51 /* doubleword64 .TOC */
#define R_PPC64_PLTGOT16	52 /* half16* M + A */
#define R_PPC64_PLTGOT16_LO	53 /* half16 #lo(M + A) */
#define R_PPC64_PLTGOT16_HI	54 /* half16 #hi(M + A) */
#define R_PPC64_PLTGOT16_HA	55 /* half16 #ha(M + A) */

#define R_PPC64_ADDR16_DS	56 /* half16ds* (S + A) >> 2 */
#define R_PPC64_ADDR16_LO_DS	57 /* half16ds  #lo(S + A) >> 2 */
#define R_PPC64_GOT16_DS	58 /* half16ds* (G + A) >> 2 */
#define R_PPC64_GOT16_LO_DS	59 /* half16ds  #lo(G + A) >> 2 */
#define R_PPC64_PLT16_LO_DS	60 /* half16ds  #lo(L + A) >> 2 */
#define R_PPC64_SECTOFF_DS	61 /* half16ds* (R + A) >> 2 */
#define R_PPC64_SECTOFF_LO_DS	62 /* half16ds  #lo(R + A) >> 2 */
#define R_PPC64_TOC16_DS	63 /* half16ds* (S + A - .TOC.) >> 2 */
#define R_PPC64_TOC16_LO_DS	64 /* half16ds  #lo(S + A - .TOC.) >> 2 */
#define R_PPC64_PLTGOT16_DS	65 /* half16ds* (M + A) >> 2 */
#define R_PPC64_PLTGOT16_LO_DS	66 /* half16ds  #lo(M + A) >> 2 */

/* PowerPC64 relocations defined for the TLS access ABI.  */
#define R_PPC64_TLS		67 /* none	(sym+add)@tls */
#define R_PPC64_DTPMOD64	68 /* doubleword64 (sym+add)@dtpmod */
#define R_PPC64_TPREL16		69 /* half16*	(sym+add)@tprel */
#define R_PPC64_TPREL16_LO	70 /* half16	(sym+add)@tprel@l */
#define R_PPC64_TPREL16_HI	71 /* half16	(sym+add)@tprel@h */
#define R_PPC64_TPREL16_HA	72 /* half16	(sym+add)@tprel@ha */
#define R_PPC64_TPREL64		73 /* doubleword64 (sym+add)@tprel */
#define R_PPC64_DTPREL16	74 /* half16*	(sym+add)@dtprel */
#define R_PPC64_DTPREL16_LO	75 /* half16	(sym+add)@dtprel@l */
#define R_PPC64_DTPREL16_HI	76 /* half16	(sym+add)@dtprel@h */
#define R_PPC64_DTPREL16_HA	77 /* half16	(sym+add)@dtprel@ha */
#define R_PPC64_DTPREL64	78 /* doubleword64 (sym+add)@dtprel */
#define R_PPC64_GOT_TLSGD16	79 /* half16*	(sym+add)@got@tlsgd */
#define R_PPC64_GOT_TLSGD16_LO	80 /* half16	(sym+add)@got@tlsgd@l */
#define R_PPC64_GOT_TLSGD16_HI	81 /* half16	(sym+add)@got@tlsgd@h */
#define R_PPC64_GOT_TLSGD16_HA	82 /* half16	(sym+add)@got@tlsgd@ha */
#define R_PPC64_GOT_TLSLD16	83 /* half16*	(sym+add)@got@tlsld */
#define R_PPC64_GOT_TLSLD16_LO	84 /* half16	(sym+add)@got@tlsld@l */
#define R_PPC64_GOT_TLSLD16_HI	85 /* half16	(sym+add)@got@tlsld@h */
#define R_PPC64_GOT_TLSLD16_HA	86 /* half16	(sym+add)@got@tlsld@ha */
#define R_PPC64_GOT_TPREL16_DS	87 /* half16ds*	(sym+add)@got@tprel */
#define R_PPC64_GOT_TPREL16_LO_DS 88 /* half16ds (sym+add)@got@tprel@l */
#define R_PPC64_GOT_TPREL16_HI	89 /* half16	(sym+add)@got@tprel@h */
#define R_PPC64_GOT_TPREL16_HA	90 /* half16	(sym+add)@got@tprel@ha */
#define R_PPC64_GOT_DTPREL16_DS	91 /* half16ds*	(sym+add)@got@dtprel */
#define R_PPC64_GOT_DTPREL16_LO_DS 92 /* half16ds (sym+add)@got@dtprel@l */
#define R_PPC64_GOT_DTPREL16_HI	93 /* half16	(sym+add)@got@dtprel@h */
#define R_PPC64_GOT_DTPREL16_HA	94 /* half16	(sym+add)@got@dtprel@ha */
#define R_PPC64_TPREL16_DS	95 /* half16ds*	(sym+add)@tprel */
#define R_PPC64_TPREL16_LO_DS	96 /* half16ds	(sym+add)@tprel@l */
#define R_PPC64_TPREL16_HIGHER	97 /* half16	(sym+add)@tprel@higher */
#define R_PPC64_TPREL16_HIGHERA	98 /* half16	(sym+add)@tprel@highera */
#define R_PPC64_TPREL16_HIGHEST	99 /* half16	(sym+add)@tprel@highest */
#define R_PPC64_TPREL16_HIGHESTA 100 /* half16	(sym+add)@tprel@highesta */
#define R_PPC64_DTPREL16_DS	101 /* half16ds* (sym+add)@dtprel */
#define R_PPC64_DTPREL16_LO_DS	102 /* half16ds	(sym+add)@dtprel@l */
#define R_PPC64_DTPREL16_HIGHER	103 /* half16	(sym+add)@dtprel@higher */
#define R_PPC64_DTPREL16_HIGHERA 104 /* half16	(sym+add)@dtprel@highera */
#define R_PPC64_DTPREL16_HIGHEST 105 /* half16	(sym+add)@dtprel@highest */
#define R_PPC64_DTPREL16_HIGHESTA 106 /* half16	(sym+add)@dtprel@highesta */
#define R_PPC64_TLSGD		107 /* none	(sym+add)@tlsgd */
#define R_PPC64_TLSLD		108 /* none	(sym+add)@tlsld */
#define R_PPC64_TOCSAVE		109 /* none */

/* Added when HA and HI relocs were changed to report overflows.  */
#define R_PPC64_ADDR16_HIGH	110
#define R_PPC64_ADDR16_HIGHA	111
#define R_PPC64_TPREL16_HIGH	112
#define R_PPC64_TPREL16_HIGHA	113
#define R_PPC64_DTPREL16_HIGH	114
#define R_PPC64_DTPREL16_HIGHA	115

/* GNU extension to support local ifunc.  */
#define R_PPC64_JMP_IREL	247
#define R_PPC64_IRELATIVE	248
#define R_PPC64_REL16		249	/* half16   (sym+add-.) */
#define R_PPC64_REL16_LO	250	/* half16   (sym+add-.)@l */
#define R_PPC64_REL16_HI	251	/* half16   (sym+add-.)@h */
#define R_PPC64_REL16_HA	252	/* half16   (sym+add-.)@ha */

/* e_flags bits specifying ABI.
   1 for original function descriptor using ABI,
   2 for revised ABI without function descriptors,
   0 for unspecified or not using any features affected by the differences.  */
#define EF_PPC64_ABI	3

/* PowerPC64 specific values for the Dyn d_tag field.  */
#define DT_PPC64_GLINK  (DT_LOPROC + 0)
#define DT_PPC64_OPD	(DT_LOPROC + 1)
#define DT_PPC64_OPDSZ	(DT_LOPROC + 2)
#define DT_PPC64_OPT	(DT_LOPROC + 3)
#define DT_PPC64_NUM    4

/* PowerPC64 specific values for the DT_PPC64_OPT Dyn entry.  */
#define PPC64_OPT_TLS		1
#define PPC64_OPT_MULTI_TOC	2

/* PowerPC64 specific values for the Elf64_Sym st_other field.  */
#define STO_PPC64_LOCAL_BIT	5
#define STO_PPC64_LOCAL_MASK	(7 << STO_PPC64_LOCAL_BIT)
#define PPC64_LOCAL_ENTRY_OFFSET(other)				\
 (((1 << (((other) & STO_PPC64_LOCAL_MASK) >> STO_PPC64_LOCAL_BIT)) >> 2) << 2)

