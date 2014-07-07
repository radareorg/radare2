/* radare - LGPL - Copyright 2014 - Fedor Sakharov */
#ifndef COFF_SPECS_H
#define COFF_SPECS_H

#include <r_types_base.h>

#define COFF_FILE_MACHINE_UNKNOWN	0x0
#define COFF_FILE_MACHINE_AM33		0x1d3
#define COFF_FILE_MACHINE_AMD64	0x8664
#define COFF_FILE_MACHINE_ARM		0x1c0
#define COFF_FILE_MACHINE_ARMNT	0x1c4
#define COFF_FILE_MACHINE_ARM64	0xaa64
#define COFF_FILE_MACHINE_EBC		0xebc
#define COFF_FILE_MACHINE_I386		0x14c
#define COFF_FILE_MACHINE_IA64		0x200
#define COFF_FILE_MACHINE_M32R		0x9041
#define COFF_FILE_MACHINE_MIPS16	0x266
#define COFF_FILE_MACHINE_MIPSFPU	0x366
#define COFF_FILE_MACHINE_MIPSFPU16	0x466
#define COFF_FILE_MACHINE_POWERPC	0x1f0
#define COFF_FILE_MACHINE_POWERPCFP	0x1f1
#define COFF_FILE_MACHINE_R4000	0x166
#define COFF_FILE_MACHINE_SH3		0x1a2
#define COFF_FILE_MACHINE_SH3DSP	0x1a3
#define COFF_FILE_MACHINE_SH4		0x1a6
#define COFF_FILE_MACHINE_SH5		0x1a8
#define COFF_FILE_MACHINE_THUMB	0x1c2
#define COFF_FILE_MACHINE_WCEMIPSV2	0x169
#define COFF_FILE_MACHINE_H8300	0x0083

#define COFF_FILE_TI_COFF		0xc1
#define COFF_FILE_MACHINE_TMS470	0x0097
#define COFF_FILE_MACHINE_TMS320C54	0x0098
#define COFF_FILE_MACHINE_TMS320C60	0x0099
#define COFF_FILE_MACHINE_TMS320C55	0x009C
#define COFF_FILE_MACHINE_TMS320C28	0x009D
#define COFF_FILE_MACHINE_MSP430	0x00A0
#define COFF_FILE_MACHINE_TMS320C55PLUS	0x00A1

#define COFF_FLAGS_TI_F_RELFLG		0x0001
#define COFF_FLAGS_TI_F_EXEC		0x0002
#define COFF_FLAGS_TI_F_LNNO		0x0004
#define COFF_FLAGS_TI_F_LSYMS		0x0008
#define COFF_FLAGS_TI_F_BIG		0x0200
#define COFF_FLAGS_TI_F_LITTLE		0x0100

#define COFF_SCN_TYPE_NO_PAD		0x00000008
#define COFF_SCN_CNT_CODE		0x00000020
#define COFF_SCN_CNT_INIT_DATA		0x00000040
#define COFF_SCN_LNK_OTHER		0x00000100
#define COFF_SCN_LNK_INFO		0x00000200
#define COFF_SCN_LNK_REMOVE		0x00000800
#define COFF_SCN_LNK_COMDAT		0x00001000
#define COFF_SCN_GPREL			0x00008000
#define COFF_SCN_MEM_PURGEABLE		0x00010000
#define COFF_SCN_MEM_16BIT		0x00020000
#define COFF_SCN_MEM_LOCKED		0x00040000
#define COFF_SCN_MEM_PRELOAD		0x00080000
#define COFF_SCN_ALIGN_1BYTES		0x00100000
#define COFF_SCN_ALIGN_2BYTES		0x00200000
#define COFF_SCN_ALIGN_4BYTES		0x00300000
#define COFF_SCN_ALIGN_8BYTES		0x00400000
#define COFF_SCN_ALIGN_16BYTES		0x00500000
#define COFF_SCN_ALIGN_32BYTES		0x00600000
#define COFF_SCN_ALIGN_64BYTES		0x00700000
#define COFF_SCN_ALIGN_128BYTES	0x00800000
#define COFF_SCN_ALIGN_256BYTES	0x00900000
#define COFF_SCN_ALIGN_512BYTES	0x00A00000
#define COFF_SCN_ALIGN_1024BYTES	0x00B00000
#define COFF_SCN_ALIGN_2048BYTES	0x00C00000
#define COFF_SCN_ALIGN_4096BYTES	0x00D00000
#define COFF_SCN_ALIGN_8192BYTES	0x00E00000
#define COFF_SCN_LNK_NRELOC_OVFL	0x01000000
#define COFF_SCN_MEM_DISCARDABLE	0x02000000
#define COFF_SCN_MEM_NOT_CACHED	0x04000000
#define COFF_SCN_MEM_NOT_PAGED		0x08000000
#define COFF_SCN_MEM_SHARED		0x10000000
#define COFF_SCN_MEM_EXECUTE		0x20000000
#define COFF_SCN_MEM_READ		0x40000000
#define COFF_SCN_MEM_WRITE		0x80000000

#define COFF_SYM_TYPE_NULL		0
#define COFF_SYM_TYPE_VOID		1
#define COFF_SYM_TYPE_CHAR		2
#define COFF_SYM_TYPE_SHORT		3
#define COFF_SYM_TYPE_INT		4
#define COFF_SYM_TYPE_LONG		5
#define COFF_SYM_TYPE_FLOAT		6
#define COFF_SYM_TYPE_DOUBLE		7
#define COFF_SYM_TYPE_STRUCT		8
#define COFF_SYM_TYPE_UNION		9
#define COFF_SYM_TYPE_ENUM		10
#define COFF_SYM_TYPE_MOE		11
#define COFF_SYM_TYPE_BYTE		12
#define COFF_SYM_TYPE_WORD		13
#define COFF_SYM_TYPE_UINT		14
#define COFF_SYM_TYPE_DWORD		15

#define COFF_SYM_DTYPE_NULL		0
#define COFF_SYM_DTYPE_POINTER		1
#define COFF_SYM_DTYPE_FUNCTION	2
#define COFF_SYM_DTYPE_ARRAY		3

#define COFF_SYM_CLASS_END_OF_FUNCTION	0xFF
#define COFF_SYM_CLASS_NULL		0
#define COFF_SYM_CLASS_AUTOMATIC	1
#define COFF_SYM_CLASS_EXTERNAL	2
#define COFF_SYM_CLASS_STATIC		3
#define COFF_SYM_CLASS_REGISTER	4
#define COFF_SYM_CLASS_EXTERNAL_DEF	5
#define COFF_SYM_CLASS_LABEL		6
#define COFF_SYM_CLASS_UNDEFINED_LABEL	7
#define COFF_SYM_CLASS_MEMBER_OF_STRUCT 8
#define COFF_SYM_CLASS_ARGUMENT	9
#define COFF_SYM_CLASS_STRUCT_TAG	10
#define COFF_SYM_CLASS_MEMBER_OF_UNION	11
#define COFF_SYM_CLASS_UNION_TAG	12
#define COFF_SYM_CLASS_TYPE_DEFINITION	13
#define COFF_SYM_CLASS_UNDEFINED_STATIC 14
#define COFF_SYM_CLASS_ENUM_TAG	15
#define COFF_SYM_CLASS_MEMBER_OF_ENUM	16
#define COFF_SYM_CLASS_REGISTER_PARAM	17
#define COFF_SYM_CLASS_BIT_FIELD	18
#define COFF_SYM_CLASS_BLOCK		100
#define COFF_SYM_CLASS_FUNCTION	101
#define COFF_SYM_CLASS_END_OF_STRUCT	102
#define COFF_SYM_CLASS_FILE		103
#define COFF_SYM_CLASS_SECTION		104
#define COFF_SYM_CLASS_WEAK_EXTERNAL	105
#define COFF_SYM_CLASS_CLR_TOKEN	107

struct coff_hdr {
	ut16 f_magic;	/* Magic number */	
	ut16 f_nscns;	/* Number of Sections */
	ut32 f_timdat;	/* Time & date stamp */
	ut32 f_symptr;	/* File pointer to Symbol Table */
	ut32 f_nsyms;	/* Number of Symbols */
	ut16 f_opthdr;	/* sizeof(Optional Header) */
	ut16 f_flags;	/* Flags */
} __attribute__((packed));

struct coff_opt_hdr {
	ut16 magic;			/* Magic Number                    */
	ut16 vstamp;		/* Version stamp                   */
	ut32 tsize;			/* Text size in bytes              */
	ut32 dsize;			/* Initialised data size           */
	ut32 bsize;			/* Uninitialised data size         */
	ut32 entry;			/* Entry point                     */
	ut32 text_start;	/* Base of Text used for this file */
	ut32 data_start;	/* Base of Data used for this file */
} __attribute__((packed));

struct coff_scn_hdr {
	char s_name[8];	/* Section Name */
	ut32 s_paddr;	/* Physical Address */
	ut32 s_vaddr;	/* Virtual Address */
	ut32 s_size;	/* Section Size in Bytes */
	ut32 s_scnptr;	/* File offset to the Section data */
	ut32 s_relptr;	/* File offset to the Relocation table for this Section */
	ut32 s_lnnoptr;	/* File offset to the Line Number table for this Section */
	ut16 s_nreloc;	/* Number of Relocation table entries */
	ut16 s_nlnno;	/* Number of Line Number table entries */
	ut32 s_flags;	/* Flags for this section */
} __attribute__((packed));

struct coff_symbol {
	char n_name[8];	/* Symbol Name */
	ut32 n_value;	/* Value of Symbol */
	ut16 n_scnum;	/* Section Number */
	ut16 n_type;	/* Symbol Type */
	ut8 n_sclass;	/* Storage Class */
	ut8 n_numaux;	/* Auxiliary Count */
} __attribute__((packed));

#endif /* COFF_SPECS_H */
