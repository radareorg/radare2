

/* SH specific declarations */

/* Processor specific flags for the ELF header e_flags field.  */
#define EF_SH_MACH_MASK		0x1f
#define EF_SH_UNKNOWN		0x0
#define EF_SH1			0x1
#define EF_SH2			0x2
#define EF_SH3			0x3
#define EF_SH_DSP		0x4
#define EF_SH3_DSP		0x5
#define EF_SH4AL_DSP		0x6
#define EF_SH3E			0x8
#define EF_SH4			0x9
#define EF_SH2E			0xb
#define EF_SH4A			0xc
#define EF_SH2A			0xd
#define EF_SH4_NOFPU		0x10
#define EF_SH4A_NOFPU		0x11
#define EF_SH4_NOMMU_NOFPU	0x12
#define EF_SH2A_NOFPU		0x13
#define EF_SH3_NOMMU		0x14
#define EF_SH2A_SH4_NOFPU	0x15
#define EF_SH2A_SH3_NOFPU	0x16
#define EF_SH2A_SH4		0x17
#define EF_SH2A_SH3E		0x18

/* SH relocs.  */
#define	R_SH_NONE		0
#define	R_SH_DIR32		1
#define	R_SH_REL32		2
#define	R_SH_DIR8WPN		3
#define	R_SH_IND12W		4
#define	R_SH_DIR8WPL		5
#define	R_SH_DIR8WPZ		6
#define	R_SH_DIR8BP		7
#define	R_SH_DIR8W		8
#define	R_SH_DIR8L		9
#define	R_SH_SWITCH16		25
#define	R_SH_SWITCH32		26
#define	R_SH_USES		27
#define	R_SH_COUNT		28
#define	R_SH_ALIGN		29
#define	R_SH_CODE		30
#define	R_SH_DATA		31
#define	R_SH_LABEL		32
#define	R_SH_SWITCH8		33
#define	R_SH_GNU_VTINHERIT	34
#define	R_SH_GNU_VTENTRY	35
#define	R_SH_TLS_GD_32		144
#define	R_SH_TLS_LD_32		145
#define	R_SH_TLS_LDO_32		146
#define	R_SH_TLS_IE_32		147
#define	R_SH_TLS_LE_32		148
#define	R_SH_TLS_DTPMOD32	149
#define	R_SH_TLS_DTPOFF32	150
#define	R_SH_TLS_TPOFF32	151
#define	R_SH_GOT32		160
#define	R_SH_PLT32		161
#define	R_SH_COPY		162
#define	R_SH_GLOB_DAT		163
#define	R_SH_JMP_SLOT		164
#define	R_SH_RELATIVE		165
#define	R_SH_GOTOFF		166
#define	R_SH_GOTPC		167
/* Keep this the last entry.  */
#define	R_SH_NUM		256
