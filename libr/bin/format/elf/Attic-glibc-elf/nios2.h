/* Legal values for d_tag (dynamic entry type).  */
#define DT_NIOS2_GP             0x70000002 /* Address of _gp.  */

/* Nios II relocations.  */
#define R_NIOS2_NONE		0	/* No reloc.  */
#define R_NIOS2_S16		1	/* Direct signed 16 bit.  */
#define R_NIOS2_U16		2	/* Direct unsigned 16 bit.  */
#define R_NIOS2_PCREL16		3	/* PC relative 16 bit.  */
#define R_NIOS2_CALL26		4	/* Direct call.  */
#define R_NIOS2_IMM5		5	/* 5 bit constant expression.  */
#define R_NIOS2_CACHE_OPX	6	/* 5 bit expression, shift 22.  */
#define R_NIOS2_IMM6		7	/* 6 bit constant expression.  */
#define R_NIOS2_IMM8		8	/* 8 bit constant expression.  */
#define R_NIOS2_HI16		9	/* High 16 bit.  */
#define R_NIOS2_LO16		10	/* Low 16 bit.  */
#define R_NIOS2_HIADJ16		11	/* High 16 bit, adjusted.  */
#define R_NIOS2_BFD_RELOC_32	12	/* 32 bit symbol value + addend.  */
#define R_NIOS2_BFD_RELOC_16	13	/* 16 bit symbol value + addend.  */
#define R_NIOS2_BFD_RELOC_8	14	/* 8 bit symbol value + addend.  */
#define R_NIOS2_GPREL		15	/* 16 bit GP pointer offset.  */
#define R_NIOS2_GNU_VTINHERIT	16	/* GNU C++ vtable hierarchy.  */
#define R_NIOS2_GNU_VTENTRY	17	/* GNU C++ vtable member usage.  */
#define R_NIOS2_UJMP		18	/* Unconditional branch.  */
#define R_NIOS2_CJMP		19	/* Conditional branch.  */
#define R_NIOS2_CALLR		20	/* Indirect call through register.  */
#define R_NIOS2_ALIGN		21	/* Alignment requirement for
					   linker relaxation.  */
#define R_NIOS2_GOT16		22	/* 16 bit GOT entry.  */
#define R_NIOS2_CALL16		23	/* 16 bit GOT entry for function.  */
#define R_NIOS2_GOTOFF_LO	24	/* %lo of offset to GOT pointer.  */
#define R_NIOS2_GOTOFF_HA	25	/* %hiadj of offset to GOT pointer.  */
#define R_NIOS2_PCREL_LO	26	/* %lo of PC relative offset.  */
#define R_NIOS2_PCREL_HA	27	/* %hiadj of PC relative offset.  */
#define R_NIOS2_TLS_GD16	28	/* 16 bit GOT offset for TLS GD.  */
#define R_NIOS2_TLS_LDM16	29	/* 16 bit GOT offset for TLS LDM.  */
#define R_NIOS2_TLS_LDO16	30	/* 16 bit module relative offset.  */
#define R_NIOS2_TLS_IE16	31	/* 16 bit GOT offset for TLS IE.  */
#define R_NIOS2_TLS_LE16	32	/* 16 bit LE TP-relative offset.  */
#define R_NIOS2_TLS_DTPMOD	33	/* Module number.  */
#define R_NIOS2_TLS_DTPREL	34	/* Module-relative offset.  */
#define R_NIOS2_TLS_TPREL	35	/* TP-relative offset.  */
#define R_NIOS2_COPY		36	/* Copy symbol at runtime.  */
#define R_NIOS2_GLOB_DAT	37	/* Create GOT entry.  */
#define R_NIOS2_JUMP_SLOT	38	/* Create PLT entry.  */
#define R_NIOS2_RELATIVE	39	/* Adjust by program base.  */
#define R_NIOS2_GOTOFF		40	/* 16 bit offset to GOT pointer.  */
#define R_NIOS2_CALL26_NOAT	41	/* Direct call in .noat section.  */
#define R_NIOS2_GOT_LO		42	/* %lo() of GOT entry.  */
#define R_NIOS2_GOT_HA		43	/* %hiadj() of GOT entry.  */
#define R_NIOS2_CALL_LO		44	/* %lo() of function GOT entry.  */
#define R_NIOS2_CALL_HA		45	/* %hiadj() of function GOT entry.  */

