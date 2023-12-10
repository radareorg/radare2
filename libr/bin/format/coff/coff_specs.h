/* radare - LGPL - Copyright 2014-2023 - Fedor Sakharov, terorie */
#ifndef COFF_SPECS_H
#define COFF_SPECS_H

#include <r_types_base.h>

/* COFF magic numbers */
#define COFF_FILE_MACHINE_UNKNOWN	0x0
#define COFF_FILE_MACHINE_AM33		0x1d3
#define COFF_FILE_MACHINE_AMD64		0x8664
#define COFF_FILE_MACHINE_ALPHA		0x184 /* MS Visual C++ (Alpha) object file */
#define COFF_FILE_MACHINE_ARM		0x1c0
#define COFF_FILE_MACHINE_ARMNT		0x1c4
#define COFF_FILE_MACHINE_ARM64		0xaa64
#define COFF_FILE_MACHINE_EBC		0xebc
#define COFF_FILE_MACHINE_I386		0x14c
#define COFF_FILE_MACHINE_IA64		0x200
#define COFF_FILE_MACHINE_M32R		0x9041
#define COFF_FILE_MACHINE_MIPS16	0x266
#define COFF_FILE_MACHINE_MIPSFPU	0x366
#define COFF_FILE_MACHINE_MIPSFPU16	0x466
#define COFF_FILE_MACHINE_AMD29K	0x17a
#define COFF_FILE_MACHINE_POWERPC	0x1f0 /* MS Visual C++ (PowerPC) object file (little endian) */
#define COFF_FILE_MACHINE_POWERPCFP	0x1f1
#define COFF_FILE_MACHINE_R4000		0x166 /* MS Visual C++ (MIPS) object file (little endian) */
#define COFF_FILE_MACHINE_SH3		0x1a2
#define COFF_FILE_MACHINE_SH3DSP	0x1a3
#define COFF_FILE_MACHINE_SH4		0x1a6
#define COFF_FILE_MACHINE_SH5		0x1a8
#define COFF_FILE_MACHINE_THUMB		0x1c2
#define COFF_FILE_MACHINE_WCEMIPSV2	0x169
#define COFF_FILE_MACHINE_H8300		0x8300
/* COFF magic numbers */
#define COFF_FILE_TI_COFF		0xc1
#define COFF_FILE_MACHINE_TMS470	0x0097
#define COFF_FILE_MACHINE_TMS320C54	0x0098
#define COFF_FILE_MACHINE_TMS320C60	0x0099
#define COFF_FILE_MACHINE_TMS320C55	0x009C
#define COFF_FILE_MACHINE_TMS320C28	0x009D
#define COFF_FILE_MACHINE_MSP430	0x00A0
#define COFF_FILE_MACHINE_TMS320C55PLUS	0x00A1
/* XCOFF32 magic numbers */
#define XCOFF32_FILE_MACHINE_U800WR	0x0198
#define XCOFF32_FILE_MACHINE_U800RO	0x019d
#define XCOFF32_FILE_MACHINE_U800TOC	0x019f
#define XCOFF32_FILE_MACHINE_U802WR	0x01d8
#define XCOFF32_FILE_MACHINE_U802RO	0x01dd
#define XCOFF32_FILE_MACHINE_U802TOC	0x01df /* IBM AIX 5.1 (PowerPC 32-bit, RO text, TOC) */
/* XCOFF64 magic numbers */
#define XCOFF64_FILE_MACHINE_U803TOC	0x1e7
#define XCOFF64_FILE_MACHINE_U803XTOC	0x1ef
#define XCOFF64_FILE_MACHINE_U64	0x1f7 /* IBM AIX (PowerPC 64-bit)  */

#define COFF_FLAGS_TI_F_RELFLG		0x0001
#define COFF_FLAGS_TI_F_EXEC		0x0002
#define COFF_FLAGS_TI_F_LNNO		0x0004
#define COFF_FLAGS_TI_F_LSYMS		0x0008
#define COFF_FLAGS_TI_F_BIG		0x0200
#define COFF_FLAGS_TI_F_LITTLE		0x0100

#define COFF_STYP_TEXT 0x20
#define COFF_STYP_DATA 0x40
#define COFF_STYP_BSS 0x80

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
#define COFF_SCN_ALIGN_128BYTES		0x00800000
#define COFF_SCN_ALIGN_256BYTES		0x00900000
#define COFF_SCN_ALIGN_512BYTES		0x00A00000
#define COFF_SCN_ALIGN_1024BYTES	0x00B00000
#define COFF_SCN_ALIGN_2048BYTES	0x00C00000
#define COFF_SCN_ALIGN_4096BYTES	0x00D00000
#define COFF_SCN_ALIGN_8192BYTES	0x00E00000
#define COFF_SCN_LNK_NRELOC_OVFL	0x01000000
#define COFF_SCN_MEM_DISCARDABLE	0x02000000
#define COFF_SCN_MEM_NOT_CACHED		0x04000000
#define COFF_SCN_MEM_NOT_PAGED		0x08000000
#define COFF_SCN_MEM_SHARED		0x10000000
#define COFF_SCN_MEM_EXECUTE		0x20000000
#define COFF_SCN_MEM_READ		0x40000000
#define COFF_SCN_MEM_WRITE		0x80000000

/* XCOFF section header flags (type) */
#define XCOFF_SCN_TYPE_REG	0x0000
#define XCOFF_SCN_TYPE_PAD	0x0008
#define XCOFF_SCN_TYPE_DWARF	0x0010
#define XCOFF_SCN_TYPE_TEXT	0x0020
#define XCOFF_SCN_TYPE_DATA	0x0040
#define XCOFF_SCN_TYPE_BSS	0x0080
#define XCOFF_SCN_TYPE_EXCEPT	0x0100
#define XCOFF_SCN_TYPE_INFO	0x0200
#define XCOFF_SCN_TYPE_TDATA	0x0400
#define XCOFF_SCN_TYPE_TBSS	0x0800
#define XCOFF_SCN_TYPE_LOADER	0x1000
#define XCOFF_SCN_TYPE_DEBUG	0x2000
#define XCOFF_SCN_TYPE_TYPCHK	0x4000
#define XCOFF_SCN_TYPE_OVRFLO	0x8000

/* XCOFF section header flags (DWARF subtype) */
#define XCOFF_SCN_SUBTYPE_DWINFO	0x10000
#define XCOFF_SCN_SUBTYPE_DWLINE	0x20000
#define XCOFF_SCN_SUBTYPE_DWPBNMS	0x30000
#define XCOFF_SCN_SUBTYPE_DWPBTYP	0x40000
#define XCOFF_SCN_SUBTYPE_DWARNGE	0x50000
#define XCOFF_SCN_SUBTYPE_DWABREV	0x60000
#define XCOFF_SCN_SUBTYPE_DWSTR		0x70000
#define XCOFF_SCN_SUBTYPE_DWRNGES	0x80000
#define XCOFF_SCN_SUBTYPE_DWLOC		0x90000
#define XCOFF_SCN_SUBTYPE_DWFRAME	0xA0000
#define XCOFF_SCN_SUBTYPE_DWMAC		0xB0000

#define COFF_SYM_SCNUM_UNDEF 		0
#define COFF_SYM_SCNUM_ABS		0xffff
#define COFF_SYM_SCNUM_DEBUG		0xfffe

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

/* Storage class (valid for COFF, XCOFF32, XCOFF64) */
#define COFF_SYM_CLASS_END_OF_FUNCTION	255
#define COFF_SYM_CLASS_NULL		  0
#define COFF_SYM_CLASS_AUTOMATIC	  1
#define COFF_SYM_CLASS_EXTERNAL		  2
#define COFF_SYM_CLASS_STATIC		  3
#define COFF_SYM_CLASS_REGISTER		  4
#define COFF_SYM_CLASS_EXTERNAL_DEF	  5
#define COFF_SYM_CLASS_LABEL		  6
#define COFF_SYM_CLASS_UNDEFINED_LABEL	  7
#define COFF_SYM_CLASS_MEMBER_OF_STRUCT   8
#define COFF_SYM_CLASS_ARGUMENT		  9
#define COFF_SYM_CLASS_STRUCT_TAG	 10
#define COFF_SYM_CLASS_MEMBER_OF_UNION	 11
#define COFF_SYM_CLASS_UNION_TAG	 12
#define COFF_SYM_CLASS_TYPE_DEFINITION	 13
#define COFF_SYM_CLASS_UNDEFINED_STATIC  14
#define COFF_SYM_CLASS_ENUM_TAG		 15
#define COFF_SYM_CLASS_MEMBER_OF_ENUM	 16
#define COFF_SYM_CLASS_REGISTER_PARAM	 17
#define COFF_SYM_CLASS_BIT_FIELD	 18
#define COFF_SYM_CLASS_BLOCK		100
#define COFF_SYM_CLASS_FUNCTION		101
#define COFF_SYM_CLASS_END_OF_STRUCT	102
#define COFF_SYM_CLASS_FILE		103
#define COFF_SYM_CLASS_SECTION		104
#define COFF_SYM_CLASS_WEAK_EXTERNAL	105
#define COFF_SYM_CLASS_CLR_TOKEN	107

/* XCOFF32 loader */
#define XCOFF_LDSYM_FLAGS(x) ((x)&0xF8)
#define XCOFF_LDSYM_FLAG_EXPORT		0x10
#define XCOFF_LDSYM_FLAG_ENTRYPOINT	0x20
#define XCOFF_LDSYM_FLAG_IMPORT		0x40

#define XCOFF_LDSYM_TYPE(x) ((x)&0x07)

#define XCOFF_LDSYM_CLASS_FUNCTION	0x0a

/* XCOFF64 auxiliary entry type */
#define XCOFF_AUX_EXCEPT	255
#define XCOFF_AUX_FCN		254
#define XCOFF_AUX_SYM		253
#define XCOFF_AUX_FILE		252
#define XCOFF_AUX_CSECT		251

#define COFF_REL_I386_ABS		0
#define COFF_REL_I386_DIR16		1
#define COFF_REL_I386_REL16		2
#define COFF_REL_I386_DIR32		6
#define COFF_REL_I386_DIR32NB		7
#define COFF_REL_I386_REL32		20

#define COFF_REL_AMD64_ABS		0
#define COFF_REL_AMD64_ADDR64		1
#define COFF_REL_AMD64_ADDR32		2
#define COFF_REL_AMD64_ADDR32_NB	3
#define COFF_REL_AMD64_REL32		4
#define COFF_REL_AMD64_REL32_1		5
#define COFF_REL_AMD64_REL32_2		6
#define COFF_REL_AMD64_REL32_3		7
#define COFF_REL_AMD64_REL32_4		8
#define COFF_REL_AMD64_REL32_5		9

#define COFF_REL_ARM_BRANCH24T		20
#define COFF_REL_ARM_BLX23T		21

#define COFF_REL_ARM64_ABSOLUTE		0
#define COFF_REL_ARM64_ADDR32		1
#define COFF_REL_ARM64_ADDR32NB		2
#define COFF_REL_ARM64_BRANCH26		3

/* Used internally only */
#define COFF_IS_BIG_ENDIAN 1
#define COFF_IS_LITTLE_ENDIAN 0

typedef enum {
	COFF_TYPE_REGULAR,
	COFF_TYPE_XCOFF,
	COFF_TYPE_BIGOBJ,
} coff_type;

static const char coff_bigobj_magic[16] = {
	0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xa9, 0x4b,
	0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8
};

R_PACKED (
	/* COFF/XCOFF32 file header */
	struct coff_hdr {
		ut16 f_magic; /* Magic number */
		ut16 f_nscns; /* Number of Sections */
		ut32 f_timdat; /* Time & date stamp */
		ut32 f_symptr; /* File pointer to Symbol Table */
		ut32 f_nsyms; /* Number of Symbols */
		ut16 f_opthdr; /* sizeof (Optional Header) */
		ut16 f_flags; /* Flags */
	}); // __attribute__ ((packed));

R_PACKED (
	struct coff_bigobj_hdr {
		ut16 sig1; /* 0x0 */
		ut16 sig2; /* 0xffff */
		ut16 version; /* 0x2 */
		ut16 f_magic; /* Magic number */
		ut32 f_timdat; /* Time & date stamp */
		ut8 uuid[16]; /* see coff_bigobj_magic */
		ut32 unused1; /* 0x0 (sizeofdata?)*/
		ut32 f_flags; /* 0x0 (flags?)*/
		ut32 unused3; /* 0x0 (metadatasize?)*/
		ut32 unused4; /* 0x0 (metadataoffset?)*/
		ut32 f_nscns; /* Number of Sections */
		ut32 f_symptr; /* File pointer to Symbol Table */
		ut32 f_nsyms; /* Number of Symbols */
	}); // __attribute__ ((packed));

/* XCOFF64 file header */
R_PACKED (
struct xcoff64_hdr {
	ut16 f_magic;	/* Magic number */
	ut16 f_nscns;	/* Number of Sections */
	ut32 f_timdat;	/* Time & date stamp */
	ut64 f_symptr;	/* File pointer to Symbol Table */
	ut16 f_opthdr;	/* sizeof (Optional Header) */
	ut16 f_flags;	/* Flags */
	ut32 f_nsyms;	/* Number of Symbols */
});

/* COFF auxiliary header */
R_PACKED (
struct coff_opt_hdr {
	ut16 magic;		/* Magic Number                    */
	ut16 vstamp;		/* Version stamp                   */
	ut32 tsize;		/* Text size in bytes              */
	ut32 dsize;		/* Initialised data size           */
	ut32 bsize;		/* Uninitialised data size         */
	ut32 entry;		/* Entry point                     */
	ut32 text_start;	/* Base of Text used for this file */
	ut32 data_start;	/* Base of Data used for this file */
});

/* XCOFF32 extended auxiliary header */
R_PACKED (
struct xcoff32_opt_hdr {
	ut32 o_toc;
	ut16 o_snentry;		/* Section number of entry point    */
	ut16 o_sntext;		/* Section number of text section   */
	ut16 o_sndata;		/* Section number of data section   */
	ut16 o_sntoc;		/* Section number of TOC            */
	ut16 o_snloader;	/* Section number of loader section */
	ut16 o_snbss;		/* Section number of bss section    */
	ut16 o_algntext;	/* Section alignment (2^n) of text section */
	ut16 o_algndata;	/* Section alignment (2^n) of data section */
	ut8  o_modtype[2];	/* Module type */
	ut8  o_cpuflag;
	ut8  o_cputype;
	ut32 o_maxstack;	/* Maximum stack size */
	ut32 o_maxdata;		/* Maximum data size */
	ut32 o_debugger;	/* Reserved for debugger */
	ut8  o_textpsize;	/* Text page size */
	ut8  o_datapsize;	/* Data page size */
	ut8  o_stackpsize;	/* Stack page size */
	ut8  o_flags;
	ut16 o_sntdata;		/* Section number of tdata section */
	ut16 o_sntbss;		/* Section number of tbss section */
});

/* XCOFF64 auxiliary header */
R_PACKED (
struct xcoff64_opt_hdr {
	ut16 magic;
	ut16 vstamp;
	ut32 o_debugger;	/* Reserved for debugger */
	ut64 text_start;	/* Virtual address of text section */
	ut64 data_start;	/* Virtual address of data section */
	ut64 o_toc;
	ut16 o_snentry;		/* Section number of entry point    */
	ut16 o_sntext;		/* Section number of text section   */
	ut16 o_sndata;		/* Section number of data section   */
	ut16 o_sntoc;		/* Section number of TOC            */
	ut16 o_snloader;	/* Section number of loader section */
	ut16 o_snbss;		/* Section number of bss section    */
	ut16 o_algntext;	/* Section alignment (2^n) of text section */
	ut16 o_algndata;	/* Section alignment (2^n) of data section */
	ut8  o_modtype[2];	/* Module type */
	ut8  o_cpuflag;
	ut8  o_cputype;
	ut8  o_textpsize;	/* Text page size */
	ut8  o_datapsize;	/* Data page size */
	ut8  o_stackpsize;	/* Stack page size */
	ut8  o_flags;
	ut64 tsize;		/* Size of text section */
	ut64 dsize;		/* Size of data section */
	ut64 bsize;		/* Size of bss section  */
	ut64 entry;		/* Entry point */
	ut64 o_maxstack;	/* Maximum stack size */
	ut64 o_maxdata;		/* Maximum data size */
	ut16 o_sntdata;		/* Section number of tdata section */
	ut16 o_sntbss;		/* Section number of tbss section */
	ut16 o_x64flags;	/* 64-bit object flags */
	ut16 o_resv3a;		/* Reserved */
	ut32 o_resv3[2];	/* Reserved */
});

/* COFF section header */
R_PACKED (
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
});

/* XCOFF64 section header */
R_PACKED (
struct xcoff64_scn_hdr {
	char s_name[8];	/* Section name */
	ut64 s_paddr;	/* Physical address */
	ut64 s_vaddr;	/* Virtual address */
	ut64 s_size;	/* Section Size in Bytes */
	ut64 s_scnptr;	/* File offset to the Section data */
	ut64 s_relptr;	/* File offset to the Relocation table for this Section */
	ut64 s_lnnoptr;	/* File offset to the Line Number table for this Section */
	ut32 s_nreloc;	/* Number of relocation entries */
	ut32 s_nlnno;	/* Number of line number entries */
	ut32 s_flags;	/* Flags for this section */
	char pad44[4];
});

/* COFF/XCOFF32 symbol */
R_PACKED (
struct coff_symbol {
	char n_name[8];	/* Symbol Name */
	ut32 n_value;	/* Value of Symbol */
	ut16 n_scnum;	/* Section Number */
	ut16 n_type;	/* Symbol Type */
	ut8 n_sclass;	/* Storage Class */
	ut8 n_numaux;	/* Auxiliary Count */
});

// Only change here vs regular coff is that
// the section number is 4 bytes
R_PACKED (
	struct coff_bigobj_symbol {
		char n_name[8]; /* Symbol Name */
		ut32 n_value; /* Value of Symbol */
		ut32 n_scnum; /* Section Number */
		ut16 n_type; /* Symbol Type */
		ut8 n_sclass; /* Storage Class */
		ut8 n_numaux; /* Auxiliary Count */
	});

#define COFF_SYM_GET_DTYPE(type) (((type) >> 4) & 3)

/* XCOFF64 symbol */
R_PACKED (
struct xcoff64_symbol {
	ut64 n_value;	/* Value of Symbol */
	ut32 n_offset;	/* Offset of Symbol Name */
	ut16 n_scnum;	/* Section Number */
	ut16 n_type;	/* Symbol Type */
	ut8  n_sclass;	/* Storage Class */
	ut8  n_numaux;	/* Auxiliary Count */
});

/* XCOFF64 symbol auxiliary entry */
R_PACKED (
union xcoff64_auxent {
	struct {
		ut8 x_pad[17];
		ut8 x_auxtype;
	} x_auxtype;

	struct {
		ut32 x_lnno;
	} x_sym;

	struct {
		ut32 x_scnlen_lo;
		ut32 x_parmhash;
		ut16 x_snhash;
		ut8  x_smtyp;
		ut8  x_smclas;
		ut32 x_scnlen_hi;
	} x_csect;

	struct {
		ut64 x_exptr;
		ut32 x_fsize;
		ut32 x_endndx;
	} x_except;

	struct {
		ut64 x_lnnoptr;
		ut32 x_fsize;
		ut32 x_endndx;
	} x_fcn;
});

R_PACKED (
union xcoff64_syment {
	struct xcoff64_symbol sym;
	union xcoff64_auxent aux;
});

/* COFF/XCOFF32 relocation */
R_PACKED (
struct coff_reloc {
	ut32 r_vaddr;	/* Reference Address */
	ut32 r_symndx;	/* Symbol index */
	ut16 r_type;	/* Type of relocation */
});

/* XCOFF64 relocation */
R_PACKED (
struct xcoff64_reloc {
	ut64 r_vaddr;
	ut32 r_symndx;
	ut16 r_type;
});

/* XCOFF32 loader header */
R_PACKED (
struct xcoff32_ldhdr {
	ut32 l_version;
	ut32 l_nsyms;
	ut32 l_nreloc;
	ut32 l_istlen;
	ut32 l_nimpid;
	ut32 l_impoff;
	ut32 l_stlen;
	ut32 l_stoff;
});

/* XCOFF64 loader header */
R_PACKED (
struct xcoff64_ldhdr {
	ut32 l_version;
	ut32 l_nsyms;
	ut32 l_nreloc;
	ut32 l_istlen;
	ut32 l_nimpid;
	ut32 l_stlen;
	ut64 l_impoff;
	ut64 l_stoff;
	ut64 l_symoff;
	ut64 l_rldoff;
});

/* XCOFF32 loader symbol */
R_PACKED (
struct xcoff32_ldsym {
	char l_name[8];
	ut32 l_value;
	ut16 l_scnum;
	ut8  l_smtype;
	ut8  l_smclas;
	ut32 l_ifile;
	ut32 l_parm;
});

/* XCOFF64 loader symbol */
R_PACKED (
struct xcoff64_ldsym {
	ut64 l_value;
	ut32 l_offset;
	ut16 l_scnum;
	ut8  l_smtype;
	ut8  l_smclas;
	ut32 l_ifile;
	ut32 l_parm;
});

/* XCOFF32 loader relocation */
R_PACKED (
struct xcoff32_ldrel {
	ut32 l_vaddr;
	ut32 l_symndx;
	ut16 l_rtype;
	ut16 l_rsecnm;
});

/* XCOFF64 loader relocation */
R_PACKED (
struct xcoff64_ldrel {
	ut64 l_vaddr;
	ut16 l_rtype;
	ut16 l_rsecnm;
	ut32 l_symndx;
});

/* XCOFF32 line number info */
R_PACKED (
struct xcoff32_lineno {
	union {
		ut32 l_symndx;
		ut32 l_paddr;
	};
	ut16 l_lnno;
});

/* XCOFF64 line number info */
R_PACKED (
struct xcoff64_lineno {
	union {
		ut32 l_symndx;
		ut64 l_paddr; /* TODO not portable */
	};
	ut32 l_lnno;
});

#endif /* COFF_SPECS_H */
