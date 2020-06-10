/* ARM-specific program header flags */
#define PF_ARM_SB		0x10000000 /* Segment contains the location
					      addressed by the static base. */
#define PF_ARM_PI		0x20000000 /* Position-independent segment.  */
#define PF_ARM_ABS		0x40000000 /* Absolute segment.  */

/* Processor specific values for the Phdr p_type field.  */
#define PT_ARM_EXIDX		(PT_LOPROC + 1)	/* ARM unwind segment.  */
/* ARM relocs.  */

#define R_ARM_NONE		0	/* No reloc */
#define R_ARM_PC24		1	/* Deprecated PC relative 26
					   bit branch.  */
#define R_ARM_ABS32		2	/* Direct 32 bit  */
#define R_ARM_REL32		3	/* PC relative 32 bit */
#define R_ARM_PC13		4
#define R_ARM_ABS16		5	/* Direct 16 bit */
#define R_ARM_ABS12		6	/* Direct 12 bit */
#define R_ARM_THM_ABS5		7	/* Direct & 0x7C (LDR, STR).  */
#define R_ARM_ABS8		8	/* Direct 8 bit */
#define R_ARM_SBREL32		9
#define R_ARM_THM_PC22		10	/* PC relative 24 bit (Thumb32 BL).  */
#define R_ARM_THM_PC8		11	/* PC relative & 0x3FC
					   (Thumb16 LDR, ADD, ADR).  */
#define R_ARM_AMP_VCALL9	12
#define R_ARM_SWI24		13	/* Obsolete static relocation.  */
#define R_ARM_TLS_DESC		13      /* Dynamic relocation.  */
#define R_ARM_THM_SWI8		14	/* Reserved.  */
#define R_ARM_XPC25		15	/* Reserved.  */
#define R_ARM_THM_XPC22		16	/* Reserved.  */
#define R_ARM_TLS_DTPMOD32	17	/* ID of module containing symbol */
#define R_ARM_TLS_DTPOFF32	18	/* Offset in TLS block */
#define R_ARM_TLS_TPOFF32	19	/* Offset in static TLS block */
#define R_ARM_COPY		20	/* Copy symbol at runtime */
#define R_ARM_GLOB_DAT		21	/* Create GOT entry */
#define R_ARM_JUMP_SLOT		22	/* Create PLT entry */
#define R_ARM_RELATIVE		23	/* Adjust by program base */
#define R_ARM_GOTOFF		24	/* 32 bit offset to GOT */
#define R_ARM_GOTPC		25	/* 32 bit PC relative offset to GOT */
#define R_ARM_GOT32		26	/* 32 bit GOT entry */
#define R_ARM_PLT32		27	/* Deprecated, 32 bit PLT address.  */
#define R_ARM_CALL		28	/* PC relative 24 bit (BL, BLX).  */
#define R_ARM_JUMP24		29	/* PC relative 24 bit
					   (B, BL<cond>).  */
#define R_ARM_THM_JUMP24	30	/* PC relative 24 bit (Thumb32 B.W).  */
#define R_ARM_BASE_ABS		31	/* Adjust by program base.  */
#define R_ARM_ALU_PCREL_7_0	32	/* Obsolete.  */
#define R_ARM_ALU_PCREL_15_8	33	/* Obsolete.  */
#define R_ARM_ALU_PCREL_23_15	34	/* Obsolete.  */
#define R_ARM_LDR_SBREL_11_0	35	/* Deprecated, prog. base relative.  */
#define R_ARM_ALU_SBREL_19_12	36	/* Deprecated, prog. base relative.  */
#define R_ARM_ALU_SBREL_27_20	37	/* Deprecated, prog. base relative.  */
#define R_ARM_TARGET1		38
#define R_ARM_SBREL31		39	/* Program base relative.  */
#define R_ARM_V4BX		40
#define R_ARM_TARGET2		41
#define R_ARM_PREL31		42	/* 32 bit PC relative.  */
#define R_ARM_MOVW_ABS_NC	43	/* Direct 16-bit (MOVW).  */
#define R_ARM_MOVT_ABS		44	/* Direct high 16-bit (MOVT).  */
#define R_ARM_MOVW_PREL_NC	45	/* PC relative 16-bit (MOVW).  */
#define R_ARM_MOVT_PREL		46	/* PC relative (MOVT).  */
#define R_ARM_THM_MOVW_ABS_NC	47	/* Direct 16 bit (Thumb32 MOVW).  */
#define R_ARM_THM_MOVT_ABS	48	/* Direct high 16 bit
					   (Thumb32 MOVT).  */
#define R_ARM_THM_MOVW_PREL_NC	49	/* PC relative 16 bit
					   (Thumb32 MOVW).  */
#define R_ARM_THM_MOVT_PREL	50	/* PC relative high 16 bit
					   (Thumb32 MOVT).  */
#define R_ARM_THM_JUMP19	51	/* PC relative 20 bit
					   (Thumb32 B<cond>.W).  */
#define R_ARM_THM_JUMP6		52	/* PC relative X & 0x7E
					   (Thumb16 CBZ, CBNZ).  */
#define R_ARM_THM_ALU_PREL_11_0	53	/* PC relative 12 bit
					   (Thumb32 ADR.W).  */
#define R_ARM_THM_PC12		54	/* PC relative 12 bit
					   (Thumb32 LDR{D,SB,H,SH}).  */
#define R_ARM_ABS32_NOI		55	/* Direct 32-bit.  */
#define R_ARM_REL32_NOI		56	/* PC relative 32-bit.  */
#define R_ARM_ALU_PC_G0_NC	57	/* PC relative (ADD, SUB).  */
#define R_ARM_ALU_PC_G0		58	/* PC relative (ADD, SUB).  */
#define R_ARM_ALU_PC_G1_NC	59	/* PC relative (ADD, SUB).  */
#define R_ARM_ALU_PC_G1		60	/* PC relative (ADD, SUB).  */
#define R_ARM_ALU_PC_G2		61	/* PC relative (ADD, SUB).  */
#define R_ARM_LDR_PC_G1		62	/* PC relative (LDR,STR,LDRB,STRB).  */
#define R_ARM_LDR_PC_G2		63	/* PC relative (LDR,STR,LDRB,STRB).  */
#define R_ARM_LDRS_PC_G0	64	/* PC relative (STR{D,H},
					   LDR{D,SB,H,SH}).  */
#define R_ARM_LDRS_PC_G1	65	/* PC relative (STR{D,H},
					   LDR{D,SB,H,SH}).  */
#define R_ARM_LDRS_PC_G2	66	/* PC relative (STR{D,H},
					   LDR{D,SB,H,SH}).  */
#define R_ARM_LDC_PC_G0		67	/* PC relative (LDC, STC).  */
#define R_ARM_LDC_PC_G1		68	/* PC relative (LDC, STC).  */
#define R_ARM_LDC_PC_G2		69	/* PC relative (LDC, STC).  */
#define R_ARM_ALU_SB_G0_NC	70	/* Program base relative (ADD,SUB).  */
#define R_ARM_ALU_SB_G0		71	/* Program base relative (ADD,SUB).  */
#define R_ARM_ALU_SB_G1_NC	72	/* Program base relative (ADD,SUB).  */
#define R_ARM_ALU_SB_G1		73	/* Program base relative (ADD,SUB).  */
#define R_ARM_ALU_SB_G2		74	/* Program base relative (ADD,SUB).  */
#define R_ARM_LDR_SB_G0		75	/* Program base relative (LDR,
					   STR, LDRB, STRB).  */
#define R_ARM_LDR_SB_G1		76	/* Program base relative
					   (LDR, STR, LDRB, STRB).  */
#define R_ARM_LDR_SB_G2		77	/* Program base relative
					   (LDR, STR, LDRB, STRB).  */
#define R_ARM_LDRS_SB_G0	78	/* Program base relative
					   (LDR, STR, LDRB, STRB).  */
#define R_ARM_LDRS_SB_G1	79	/* Program base relative
					   (LDR, STR, LDRB, STRB).  */
#define R_ARM_LDRS_SB_G2	80	/* Program base relative
					   (LDR, STR, LDRB, STRB).  */
#define R_ARM_LDC_SB_G0		81	/* Program base relative (LDC,STC).  */
#define R_ARM_LDC_SB_G1		82	/* Program base relative (LDC,STC).  */
#define R_ARM_LDC_SB_G2		83	/* Program base relative (LDC,STC).  */
#define R_ARM_MOVW_BREL_NC	84	/* Program base relative 16
					   bit (MOVW).  */
#define R_ARM_MOVT_BREL		85	/* Program base relative high
					   16 bit (MOVT).  */
#define R_ARM_MOVW_BREL		86	/* Program base relative 16
					   bit (MOVW).  */
#define R_ARM_THM_MOVW_BREL_NC	87	/* Program base relative 16
					   bit (Thumb32 MOVW).  */
#define R_ARM_THM_MOVT_BREL	88	/* Program base relative high
					   16 bit (Thumb32 MOVT).  */
#define R_ARM_THM_MOVW_BREL	89	/* Program base relative 16
					   bit (Thumb32 MOVW).  */
#define R_ARM_TLS_GOTDESC	90
#define R_ARM_TLS_CALL		91
#define R_ARM_TLS_DESCSEQ	92	/* TLS relaxation.  */
#define R_ARM_THM_TLS_CALL	93
#define R_ARM_PLT32_ABS		94
#define R_ARM_GOT_ABS		95	/* GOT entry.  */
#define R_ARM_GOT_PREL		96	/* PC relative GOT entry.  */
#define R_ARM_GOT_BREL12	97	/* GOT entry relative to GOT
					   origin (LDR).  */
#define R_ARM_GOTOFF12		98	/* 12 bit, GOT entry relative
					   to GOT origin (LDR, STR).  */
#define R_ARM_GOTRELAX		99
#define R_ARM_GNU_VTENTRY	100
#define R_ARM_GNU_VTINHERIT	101
#define R_ARM_THM_PC11		102	/* PC relative & 0xFFE (Thumb16 B).  */
#define R_ARM_THM_PC9		103	/* PC relative & 0x1FE
					   (Thumb16 B/B<cond>).  */
#define R_ARM_TLS_GD32		104	/* PC-rel 32 bit for global dynamic
					   thread local data */
#define R_ARM_TLS_LDM32		105	/* PC-rel 32 bit for local dynamic
					   thread local data */
#define R_ARM_TLS_LDO32		106	/* 32 bit offset relative to TLS
					   block */
#define R_ARM_TLS_IE32		107	/* PC-rel 32 bit for GOT entry of
					   static TLS block offset */
#define R_ARM_TLS_LE32		108	/* 32 bit offset relative to static
					   TLS block */
#define R_ARM_TLS_LDO12		109	/* 12 bit relative to TLS
					   block (LDR, STR).  */
#define R_ARM_TLS_LE12		110	/* 12 bit relative to static
					   TLS block (LDR, STR).  */
#define R_ARM_TLS_IE12GP	111	/* 12 bit GOT entry relative
					   to GOT origin (LDR).  */
#define R_ARM_ME_TOO		128	/* Obsolete.  */
#define R_ARM_THM_TLS_DESCSEQ	129
#define R_ARM_THM_TLS_DESCSEQ16	129
#define R_ARM_THM_TLS_DESCSEQ32	130
#define R_ARM_THM_GOT_BREL12	131	/* GOT entry relative to GOT
					   origin, 12 bit (Thumb32 LDR).  */
#define R_ARM_IRELATIVE		160
#define R_ARM_RXPC25		249
#define R_ARM_RSBREL32		250
#define R_ARM_THM_RPC22		251
#define R_ARM_RREL32		252
#define R_ARM_RABS22		253
#define R_ARM_RPC24		254
#define R_ARM_RBASE		255
/* Keep this the last entry.  */
#define R_ARM_NUM		256


/* ARM specific declarations */

/* Processor specific flags for the ELF header e_flags field.  */
#define EF_ARM_RELEXEC		0x01
#define EF_ARM_HASENTRY		0x02
#define EF_ARM_INTERWORK	0x04
#define EF_ARM_APCS_26		0x08
#define EF_ARM_APCS_FLOAT	0x10
#define EF_ARM_PIC		0x20
#define EF_ARM_ALIGN8		0x40 /* 8-bit structure alignment is in use */
#define EF_ARM_NEW_ABI		0x80
#define EF_ARM_OLD_ABI		0x100
#define EF_ARM_SOFT_FLOAT	0x200
#define EF_ARM_VFP_FLOAT	0x400
#define EF_ARM_MAVERICK_FLOAT	0x800

#define EF_ARM_ABI_FLOAT_SOFT	0x200   /* NB conflicts with EF_ARM_SOFT_FLOAT */
#define EF_ARM_ABI_FLOAT_HARD	0x400   /* NB conflicts with EF_ARM_VFP_FLOAT */


/* Other constants defined in the ARM ELF spec. version B-01.  */
/* NB. These conflict with values defined above.  */
#define EF_ARM_SYMSARESORTED	0x04
#define EF_ARM_DYNSYMSUSESEGIDX	0x08
#define EF_ARM_MAPSYMSFIRST	0x10
#define EF_ARM_EABIMASK		0XFF000000

/* Constants defined in AAELF.  */
#define EF_ARM_BE8	    0x00800000
#define EF_ARM_LE8	    0x00400000

#define EF_ARM_EABI_VERSION(flags)	((flags) & EF_ARM_EABIMASK)
#define EF_ARM_EABI_UNKNOWN	0x00000000
#define EF_ARM_EABI_VER1	0x01000000
#define EF_ARM_EABI_VER2	0x02000000
#define EF_ARM_EABI_VER3	0x03000000
#define EF_ARM_EABI_VER4	0x04000000
#define EF_ARM_EABI_VER5	0x05000000

/* Additional symbol types for Thumb.  */
#define STT_ARM_TFUNC		STT_LOPROC /* A Thumb function.  */
#define STT_ARM_16BIT		STT_HIPROC /* A Thumb label.  */

/* ARM-specific values for sh_flags */
#define SHF_ARM_ENTRYSECT	0x10000000 /* Section contains an entry point */
#define SHF_ARM_COMDEF		0x80000000 /* Section may be multiply defined
					      in the input to a link step.  */

/* Processor specific values for the Shdr sh_type field.  */
#define SHT_ARM_EXIDX		(SHT_LOPROC + 1) /* ARM unwind section.  */
#define SHT_ARM_PREEMPTMAP	(SHT_LOPROC + 2) /* Preemption details.  */
#define SHT_ARM_ATTRIBUTES	(SHT_LOPROC + 3) /* ARM attributes section.  */
