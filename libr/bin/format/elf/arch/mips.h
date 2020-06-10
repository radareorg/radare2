

/* MIPS R3000 specific definitions.  */

/* Legal values for e_flags field of Elf32_Ehdr.  */

#define EF_MIPS_NOREORDER	1     /* A .noreorder directive was used.  */
#define EF_MIPS_PIC		2     /* Contains PIC code.  */
#define EF_MIPS_CPIC		4     /* Uses PIC calling sequence.  */
#define EF_MIPS_XGOT		8
#define EF_MIPS_64BIT_WHIRL	16
#define EF_MIPS_ABI2		32
#define EF_MIPS_ABI_ON32	64
#define EF_MIPS_FP64		512  /* Uses FP64 (12 callee-saved).  */
#define EF_MIPS_NAN2008	1024  /* Uses IEEE 754-2008 NaN encoding.  */
#define EF_MIPS_ARCH		0xf0000000 /* MIPS architecture level.  */

/* Legal values for MIPS architecture level.  */

#define EF_MIPS_ARCH_1		0x00000000 /* -mips1 code.  */
#define EF_MIPS_ARCH_2		0x10000000 /* -mips2 code.  */
#define EF_MIPS_ARCH_3		0x20000000 /* -mips3 code.  */
#define EF_MIPS_ARCH_4		0x30000000 /* -mips4 code.  */
#define EF_MIPS_ARCH_5		0x40000000 /* -mips5 code.  */
#define EF_MIPS_ARCH_32		0x50000000 /* MIPS32 code.  */
#define EF_MIPS_ARCH_64		0x60000000 /* MIPS64 code.  */
#define EF_MIPS_ARCH_32R2	0x70000000 /* MIPS32r2 code.  */
#define EF_MIPS_ARCH_64R2	0x80000000 /* MIPS64r2 code.  */

/* The following are unofficial names and should not be used.  */

#define E_MIPS_ARCH_1		EF_MIPS_ARCH_1
#define E_MIPS_ARCH_2		EF_MIPS_ARCH_2
#define E_MIPS_ARCH_3		EF_MIPS_ARCH_3
#define E_MIPS_ARCH_4		EF_MIPS_ARCH_4
#define E_MIPS_ARCH_5		EF_MIPS_ARCH_5
#define E_MIPS_ARCH_32		EF_MIPS_ARCH_32
#define E_MIPS_ARCH_64		EF_MIPS_ARCH_64

/* Special section indices.  */

#define SHN_MIPS_ACOMMON	0xff00	/* Allocated common symbols.  */
#define SHN_MIPS_TEXT		0xff01	/* Allocated test symbols.  */
#define SHN_MIPS_DATA		0xff02	/* Allocated data symbols.  */
#define SHN_MIPS_SCOMMON 	0xff03	/* Small common symbols.  */
#define SHN_MIPS_SUNDEFINED	0xff04	/* Small undefined symbols.  */

/* Legal values for sh_type field of Elf32_Shdr.  */

#define SHT_MIPS_LIBLIST	0x70000000 /* Shared objects used in link.  */
#define SHT_MIPS_MSYM		0x70000001
#define SHT_MIPS_CONFLICT	0x70000002 /* Conflicting symbols.  */
#define SHT_MIPS_GPTAB		0x70000003 /* Global data area sizes.  */
#define SHT_MIPS_UCODE		0x70000004 /* Reserved for SGI/MIPS compilers */
#define SHT_MIPS_DEBUG		0x70000005 /* MIPS ECOFF debugging info.  */
#define SHT_MIPS_REGINFO	0x70000006 /* Register usage information.  */
#define SHT_MIPS_PACKAGE	0x70000007
#define SHT_MIPS_PACKSYM	0x70000008
#define SHT_MIPS_RELD		0x70000009
#define SHT_MIPS_IFACE		0x7000000b
#define SHT_MIPS_CONTENT	0x7000000c
#define SHT_MIPS_OPTIONS	0x7000000d /* Miscellaneous options.  */
#define SHT_MIPS_SHDR		0x70000010
#define SHT_MIPS_FDESC		0x70000011
#define SHT_MIPS_EXTSYM		0x70000012
#define SHT_MIPS_DENSE		0x70000013
#define SHT_MIPS_PDESC		0x70000014
#define SHT_MIPS_LOCSYM		0x70000015
#define SHT_MIPS_AUXSYM		0x70000016
#define SHT_MIPS_OPTSYM		0x70000017
#define SHT_MIPS_LOCSTR		0x70000018
#define SHT_MIPS_LINE		0x70000019
#define SHT_MIPS_RFDESC		0x7000001a
#define SHT_MIPS_DELTASYM	0x7000001b
#define SHT_MIPS_DELTAINST	0x7000001c
#define SHT_MIPS_DELTACLASS	0x7000001d
#define SHT_MIPS_DWARF		0x7000001e /* DWARF debugging information.  */
#define SHT_MIPS_DELTADECL	0x7000001f
#define SHT_MIPS_SYMBOL_LIB	0x70000020
#define SHT_MIPS_EVENTS		0x70000021 /* Event section.  */
#define SHT_MIPS_TRANSLATE	0x70000022
#define SHT_MIPS_PIXIE		0x70000023
#define SHT_MIPS_XLATE		0x70000024
#define SHT_MIPS_XLATE_DEBUG	0x70000025
#define SHT_MIPS_WHIRL		0x70000026
#define SHT_MIPS_EH_REGION	0x70000027
#define SHT_MIPS_XLATE_OLD	0x70000028
#define SHT_MIPS_PDR_EXCEPTION	0x70000029

/* Legal values for sh_flags field of Elf32_Shdr.  */

#define SHF_MIPS_GPREL		0x10000000 /* Must be in global data area.  */
#define SHF_MIPS_MERGE		0x20000000
#define SHF_MIPS_ADDR		0x40000000
#define SHF_MIPS_STRINGS	0x80000000
#define SHF_MIPS_NOSTRIP	0x08000000
#define SHF_MIPS_LOCAL		0x04000000
#define SHF_MIPS_NAMES		0x02000000
#define SHF_MIPS_NODUPE		0x01000000


/* Symbol tables.  */

/* MIPS specific values for `st_other'.  */
#define STO_MIPS_DEFAULT		0x0
#define STO_MIPS_INTERNAL		0x1
#define STO_MIPS_HIDDEN			0x2
#define STO_MIPS_PROTECTED		0x3
#define STO_MIPS_PLT			0x8
#define STO_MIPS_SC_ALIGN_UNUSED	0xff

/* MIPS specific values for `st_info'.  */
#define STB_MIPS_SPLIT_COMMON		13

/* Entries found in sections of type SHT_MIPS_GPTAB.  */

typedef union
{
  struct
    {
      Elf32_Word gt_current_g_value;	/* -G value used for compilation.  */
      Elf32_Word gt_unused;		/* Not used.  */
    } gt_header;			/* First entry in section.  */
  struct
    {
      Elf32_Word gt_g_value;		/* If this value were used for -G.  */
      Elf32_Word gt_bytes;		/* This many bytes would be used.  */
    } gt_entry;				/* Subsequent entries in section.  */
} Elf32_gptab;

/* Entry found in sections of type SHT_MIPS_REGINFO.  */

typedef struct
{
  Elf32_Word ri_gprmask;		/* General registers used.  */
  Elf32_Word ri_cprmask[4];		/* Coprocessor registers used.  */
  Elf32_Sword ri_gp_value;		/* $gp register value.  */
} Elf32_RegInfo;

/* Entries found in sections of type SHT_MIPS_OPTIONS.  */

typedef struct
{
  unsigned char kind;		/* Determines interpretation of the
				   variable part of descriptor.  */
  unsigned char size;		/* Size of descriptor, including header.  */
  Elf32_Section section;	/* Section header index of section affected,
				   0 for global options.  */
  Elf32_Word info;		/* Kind-specific information.  */
} Elf_Options;

/* MIPS relocs.  */

#define R_MIPS_NONE		0	/* No reloc */
#define R_MIPS_16		1	/* Direct 16 bit */
#define R_MIPS_32		2	/* Direct 32 bit */
#define R_MIPS_REL32		3	/* PC relative 32 bit */
#define R_MIPS_26		4	/* Direct 26 bit shifted */
#define R_MIPS_HI16		5	/* High 16 bit */
#define R_MIPS_LO16		6	/* Low 16 bit */
#define R_MIPS_GPREL16		7	/* GP relative 16 bit */
#define R_MIPS_LITERAL		8	/* 16 bit literal entry */
#define R_MIPS_GOT16		9	/* 16 bit GOT entry */
#define R_MIPS_PC16		10	/* PC relative 16 bit */
#define R_MIPS_CALL16		11	/* 16 bit GOT entry for function */
#define R_MIPS_GPREL32		12	/* GP relative 32 bit */

#define R_MIPS_SHIFT5		16
#define R_MIPS_SHIFT6		17
#define R_MIPS_64		18
#define R_MIPS_GOT_DISP		19
#define R_MIPS_GOT_PAGE		20
#define R_MIPS_GOT_OFST		21
#define R_MIPS_GOT_HI16		22
#define R_MIPS_GOT_LO16		23
#define R_MIPS_SUB		24
#define R_MIPS_INSERT_A		25
#define R_MIPS_INSERT_B		26
#define R_MIPS_DELETE		27
#define R_MIPS_HIGHER		28
#define R_MIPS_HIGHEST		29
#define R_MIPS_CALL_HI16	30
#define R_MIPS_CALL_LO16	31
#define R_MIPS_SCN_DISP		32
#define R_MIPS_REL16		33
#define R_MIPS_ADD_IMMEDIATE	34
#define R_MIPS_PJUMP		35
#define R_MIPS_RELGOT		36
#define R_MIPS_JALR		37
#define R_MIPS_TLS_DTPMOD32	38	/* Module number 32 bit */
#define R_MIPS_TLS_DTPREL32	39	/* Module-relative offset 32 bit */
#define R_MIPS_TLS_DTPMOD64	40	/* Module number 64 bit */
#define R_MIPS_TLS_DTPREL64	41	/* Module-relative offset 64 bit */
#define R_MIPS_TLS_GD		42	/* 16 bit GOT offset for GD */
#define R_MIPS_TLS_LDM		43	/* 16 bit GOT offset for LDM */
#define R_MIPS_TLS_DTPREL_HI16	44	/* Module-relative offset, high 16 bits */
#define R_MIPS_TLS_DTPREL_LO16	45	/* Module-relative offset, low 16 bits */
#define R_MIPS_TLS_GOTTPREL	46	/* 16 bit GOT offset for IE */
#define R_MIPS_TLS_TPREL32	47	/* TP-relative offset, 32 bit */
#define R_MIPS_TLS_TPREL64	48	/* TP-relative offset, 64 bit */
#define R_MIPS_TLS_TPREL_HI16	49	/* TP-relative offset, high 16 bits */
#define R_MIPS_TLS_TPREL_LO16	50	/* TP-relative offset, low 16 bits */
#define R_MIPS_GLOB_DAT		51
#define R_MIPS_COPY		126
#define R_MIPS_JUMP_SLOT        127
/* Keep this the last entry.  */
#define R_MIPS_NUM		128

/* Legal values for p_type field of Elf32_Phdr.  */

#define PT_MIPS_REGINFO	  0x70000000	/* Register usage information. */
#define PT_MIPS_RTPROC	  0x70000001	/* Runtime procedure table. */
#define PT_MIPS_OPTIONS	  0x70000002
#define PT_MIPS_ABIFLAGS  0x70000003	/* FP mode requirement. */

/* Special program header types.  */

#define PF_MIPS_LOCAL	0x10000000

/* Legal values for d_tag field of Elf32_Dyn.  */

#define DT_MIPS_RLD_VERSION  0x70000001	/* Runtime linker interface version */
#define DT_MIPS_TIME_STAMP   0x70000002	/* Timestamp */
#define DT_MIPS_ICHECKSUM    0x70000003	/* Checksum */
#define DT_MIPS_IVERSION     0x70000004	/* Version string (string tbl index) */
#define DT_MIPS_FLAGS	     0x70000005	/* Flags */
#define DT_MIPS_BASE_ADDRESS 0x70000006	/* Base address */
#define DT_MIPS_MSYM	     0x70000007
#define DT_MIPS_CONFLICT     0x70000008	/* Address of CONFLICT section */
#define DT_MIPS_LIBLIST	     0x70000009	/* Address of LIBLIST section */
#define DT_MIPS_LOCAL_GOTNO  0x7000000a	/* Number of local GOT entries */
#define DT_MIPS_CONFLICTNO   0x7000000b	/* Number of CONFLICT entries */
#define DT_MIPS_LIBLISTNO    0x70000010	/* Number of LIBLIST entries */
#define DT_MIPS_SYMTABNO     0x70000011	/* Number of DYNSYM entries */
#define DT_MIPS_UNREFEXTNO   0x70000012	/* First external DYNSYM */
#define DT_MIPS_GOTSYM	     0x70000013	/* First GOT entry in DYNSYM */
#define DT_MIPS_HIPAGENO     0x70000014	/* Number of GOT page table entries */
#define DT_MIPS_RLD_MAP	     0x70000016	/* Address of run time loader map.  */
#define DT_MIPS_DELTA_CLASS  0x70000017	/* Delta C++ class definition.  */
#define DT_MIPS_DELTA_CLASS_NO    0x70000018 /* Number of entries in
						DT_MIPS_DELTA_CLASS.  */
#define DT_MIPS_DELTA_INSTANCE    0x70000019 /* Delta C++ class instances.  */
#define DT_MIPS_DELTA_INSTANCE_NO 0x7000001a /* Number of entries in
						DT_MIPS_DELTA_INSTANCE.  */
#define DT_MIPS_DELTA_RELOC  0x7000001b /* Delta relocations.  */
#define DT_MIPS_DELTA_RELOC_NO 0x7000001c /* Number of entries in
					     DT_MIPS_DELTA_RELOC.  */
#define DT_MIPS_DELTA_SYM    0x7000001d /* Delta symbols that Delta
					   relocations refer to.  */
#define DT_MIPS_DELTA_SYM_NO 0x7000001e /* Number of entries in
					   DT_MIPS_DELTA_SYM.  */
#define DT_MIPS_DELTA_CLASSSYM 0x70000020 /* Delta symbols that hold the
					     class declaration.  */
#define DT_MIPS_DELTA_CLASSSYM_NO 0x70000021 /* Number of entries in
						DT_MIPS_DELTA_CLASSSYM.  */
#define DT_MIPS_CXX_FLAGS    0x70000022 /* Flags indicating for C++ flavor.  */
#define DT_MIPS_PIXIE_INIT   0x70000023
#define DT_MIPS_SYMBOL_LIB   0x70000024
#define DT_MIPS_LOCALPAGE_GOTIDX 0x70000025
#define DT_MIPS_LOCAL_GOTIDX 0x70000026
#define DT_MIPS_HIDDEN_GOTIDX 0x70000027
#define DT_MIPS_PROTECTED_GOTIDX 0x70000028
#define DT_MIPS_OPTIONS	     0x70000029 /* Address of .options.  */
#define DT_MIPS_INTERFACE    0x7000002a /* Address of .interface.  */
#define DT_MIPS_DYNSTR_ALIGN 0x7000002b
#define DT_MIPS_INTERFACE_SIZE 0x7000002c /* Size of the .interface section. */
#define DT_MIPS_RLD_TEXT_RESOLVE_ADDR 0x7000002d /* Address of rld_text_rsolve
						    function stored in GOT.  */
#define DT_MIPS_PERF_SUFFIX  0x7000002e /* Default suffix of dso to be added
					   by rld on dlopen() calls.  */
#define DT_MIPS_COMPACT_SIZE 0x7000002f /* (O32)Size of compact rel section. */
#define DT_MIPS_GP_VALUE     0x70000030 /* GP value for aux GOTs.  */
#define DT_MIPS_AUX_DYNAMIC  0x70000031 /* Address of aux .dynamic.  */
/* The address of .got.plt in an executable using the new non-PIC ABI.  */
#define DT_MIPS_PLTGOT	     0x70000032
/* The base of the PLT in an executable using the new non-PIC ABI if that
   PLT is writable.  For a non-writable PLT, this is omitted or has a zero
   value.  */
#define DT_MIPS_RWPLT        0x70000034
/* An alternative description of the classic MIPS RLD_MAP that is usable
   in a PIE as it stores a relative offset from the address of the tag
   rather than an absolute address.  */
#define DT_MIPS_RLD_MAP_REL  0x70000035
#define DT_MIPS_NUM	     0x36

/* Legal values for DT_MIPS_FLAGS Elf32_Dyn entry.  */

#define RHF_NONE		   0		/* No flags */
#define RHF_QUICKSTART		   (1 << 0)	/* Use quickstart */
#define RHF_NOTPOT		   (1 << 1)	/* Hash size not power of 2 */
#define RHF_NO_LIBRARY_REPLACEMENT (1 << 2)	/* Ignore LD_LIBRARY_PATH */
#define RHF_NO_MOVE		   (1 << 3)
#define RHF_SGI_ONLY		   (1 << 4)
#define RHF_GUARANTEE_INIT	   (1 << 5)
#define RHF_DELTA_C_PLUS_PLUS	   (1 << 6)
#define RHF_GUARANTEE_START_INIT   (1 << 7)
#define RHF_PIXIE		   (1 << 8)
#define RHF_DEFAULT_DELAY_LOAD	   (1 << 9)
#define RHF_REQUICKSTART	   (1 << 10)
#define RHF_REQUICKSTARTED	   (1 << 11)
#define RHF_CORD		   (1 << 12)
#define RHF_NO_UNRES_UNDEF	   (1 << 13)
#define RHF_RLD_ORDER_SAFE	   (1 << 14)

/* Entries found in sections of type SHT_MIPS_LIBLIST.  */

typedef struct
{
  Elf32_Word l_name;		/* Name (string table index) */
  Elf32_Word l_time_stamp;	/* Timestamp */
  Elf32_Word l_checksum;	/* Checksum */
  Elf32_Word l_version;		/* Interface version */
  Elf32_Word l_flags;		/* Flags */
} Elf32_Lib;

typedef struct
{
  Elf64_Word l_name;		/* Name (string table index) */
  Elf64_Word l_time_stamp;	/* Timestamp */
  Elf64_Word l_checksum;	/* Checksum */
  Elf64_Word l_version;		/* Interface version */
  Elf64_Word l_flags;		/* Flags */
} Elf64_Lib;


/* Legal values for l_flags.  */

#define LL_NONE		  0
#define LL_EXACT_MATCH	  (1 << 0)	/* Require exact match */
#define LL_IGNORE_INT_VER (1 << 1)	/* Ignore interface version */
#define LL_REQUIRE_MINOR  (1 << 2)
#define LL_EXPORTS	  (1 << 3)
#define LL_DELAY_LOAD	  (1 << 4)
#define LL_DELTA	  (1 << 5)

/* Entries found in sections of type SHT_MIPS_CONFLICT.  */

typedef Elf32_Addr Elf32_Conflict;

typedef struct
{
  /* Version of flags structure.  */
  Elf32_Half version;
  /* The level of the ISA: 1-5, 32, 64.  */
  unsigned char isa_level;
  /* The revision of ISA: 0 for MIPS V and below, 1-n otherwise.  */
  unsigned char isa_rev;
  /* The size of general purpose registers.  */
  unsigned char gpr_size;
  /* The size of co-processor 1 registers.  */
  unsigned char cpr1_size;
  /* The size of co-processor 2 registers.  */
  unsigned char cpr2_size;
  /* The floating-point ABI.  */
  unsigned char fp_abi;
  /* Processor-specific extension.  */
  Elf32_Word isa_ext;
  /* Mask of ASEs used.  */
  Elf32_Word ases;
  /* Mask of general flags.  */
  Elf32_Word flags1;
  Elf32_Word flags2;
} Elf_MIPS_ABIFlags_v0;

/* Values for the register size bytes of an abi flags structure.  */

#define MIPS_AFL_REG_NONE	0x00	 /* No registers.  */
#define MIPS_AFL_REG_32		0x01	 /* 32-bit registers.  */
#define MIPS_AFL_REG_64		0x02	 /* 64-bit registers.  */
#define MIPS_AFL_REG_128	0x03	 /* 128-bit registers.  */

/* Masks for the ases word of an ABI flags structure.  */

#define MIPS_AFL_ASE_DSP	0x00000001 /* DSP ASE.  */
#define MIPS_AFL_ASE_DSPR2	0x00000002 /* DSP R2 ASE.  */
#define MIPS_AFL_ASE_EVA	0x00000004 /* Enhanced VA Scheme.  */
#define MIPS_AFL_ASE_MCU	0x00000008 /* MCU (MicroController) ASE.  */
#define MIPS_AFL_ASE_MDMX	0x00000010 /* MDMX ASE.  */
#define MIPS_AFL_ASE_MIPS3D	0x00000020 /* MIPS-3D ASE.  */
#define MIPS_AFL_ASE_MT		0x00000040 /* MT ASE.  */
#define MIPS_AFL_ASE_SMARTMIPS	0x00000080 /* SmartMIPS ASE.  */
#define MIPS_AFL_ASE_VIRT	0x00000100 /* VZ ASE.  */
#define MIPS_AFL_ASE_MSA	0x00000200 /* MSA ASE.  */
#define MIPS_AFL_ASE_MIPS16	0x00000400 /* MIPS16 ASE.  */
#define MIPS_AFL_ASE_MICROMIPS	0x00000800 /* MICROMIPS ASE.  */
#define MIPS_AFL_ASE_XPA	0x00001000 /* XPA ASE.  */
#define MIPS_AFL_ASE_MASK	0x00001fff /* All ASEs.  */

/* Values for the isa_ext word of an ABI flags structure.  */

#define MIPS_AFL_EXT_XLR	  1   /* RMI Xlr instruction.  */
#define MIPS_AFL_EXT_OCTEON2	  2   /* Cavium Networks Octeon2.  */
#define MIPS_AFL_EXT_OCTEONP	  3   /* Cavium Networks OcteonP.  */
#define MIPS_AFL_EXT_LOONGSON_3A  4   /* Loongson 3A.  */
#define MIPS_AFL_EXT_OCTEON	  5   /* Cavium Networks Octeon.  */
#define MIPS_AFL_EXT_5900	  6   /* MIPS R5900 instruction.  */
#define MIPS_AFL_EXT_4650	  7   /* MIPS R4650 instruction.  */
#define MIPS_AFL_EXT_4010	  8   /* LSI R4010 instruction.  */
#define MIPS_AFL_EXT_4100	  9   /* NEC VR4100 instruction.  */
#define MIPS_AFL_EXT_3900	  10  /* Toshiba R3900 instruction.  */
#define MIPS_AFL_EXT_10000	  11  /* MIPS R10000 instruction.  */
#define MIPS_AFL_EXT_SB1	  12  /* Broadcom SB-1 instruction.  */
#define MIPS_AFL_EXT_4111	  13  /* NEC VR4111/VR4181 instruction.  */
#define MIPS_AFL_EXT_4120	  14  /* NEC VR4120 instruction.  */
#define MIPS_AFL_EXT_5400	  15  /* NEC VR5400 instruction.  */
#define MIPS_AFL_EXT_5500	  16  /* NEC VR5500 instruction.  */
#define MIPS_AFL_EXT_LOONGSON_2E  17  /* ST Microelectronics Loongson 2E.  */
#define MIPS_AFL_EXT_LOONGSON_2F  18  /* ST Microelectronics Loongson 2F.  */

/* Masks for the flags1 word of an ABI flags structure.  */
#define MIPS_AFL_FLAGS1_ODDSPREG  1  /* Uses odd single-precision registers.  */

/* Object attribute values.  */
enum
{
  /* Not tagged or not using any ABIs affected by the differences.  */
  Val_GNU_MIPS_ABI_FP_ANY = 0,
  /* Using hard-float -mdouble-float.  */
  Val_GNU_MIPS_ABI_FP_DOUBLE = 1,
  /* Using hard-float -msingle-float.  */
  Val_GNU_MIPS_ABI_FP_SINGLE = 2,
  /* Using soft-float.  */
  Val_GNU_MIPS_ABI_FP_SOFT = 3,
  /* Using -mips32r2 -mfp64.  */
  Val_GNU_MIPS_ABI_FP_OLD_64 = 4,
  /* Using -mfpxx.  */
  Val_GNU_MIPS_ABI_FP_XX = 5,
  /* Using -mips32r2 -mfp64.  */
  Val_GNU_MIPS_ABI_FP_64 = 6,
  /* Using -mips32r2 -mfp64 -mno-odd-spreg.  */
  Val_GNU_MIPS_ABI_FP_64A = 7,
  /* Maximum allocated FP ABI value.  */
  Val_GNU_MIPS_ABI_FP_MAX = 7
};

/* Values for `kind' field in Elf_Options.  */

#define ODK_NULL	0	/* Undefined.  */
#define ODK_REGINFO	1	/* Register usage information.  */
#define ODK_EXCEPTIONS	2	/* Exception processing options.  */
#define ODK_PAD		3	/* Section padding options.  */
#define ODK_HWPATCH	4	/* Hardware workarounds performed */
#define ODK_FILL	5	/* record the fill value used by the linker. */
#define ODK_TAGS	6	/* reserve space for desktop tools to write. */
#define ODK_HWAND	7	/* HW workarounds.  'AND' bits when merging. */
#define ODK_HWOR	8	/* HW workarounds.  'OR' bits when merging.  */

/* Values for `info' in Elf_Options for ODK_EXCEPTIONS entries.  */

#define OEX_FPU_MIN	0x1f	/* FPE's which MUST be enabled.  */
#define OEX_FPU_MAX	0x1f00	/* FPE's which MAY be enabled.  */
#define OEX_PAGE0	0x10000	/* page zero must be mapped.  */
#define OEX_SMM		0x20000	/* Force sequential memory mode?  */
#define OEX_FPDBUG	0x40000	/* Force floating point debug mode?  */
#define OEX_PRECISEFP	OEX_FPDBUG
#define OEX_DISMISS	0x80000	/* Dismiss invalid address faults?  */

#define OEX_FPU_INVAL	0x10
#define OEX_FPU_DIV0	0x08
#define OEX_FPU_OFLO	0x04
#define OEX_FPU_UFLO	0x02
#define OEX_FPU_INEX	0x01

/* Masks for `info' in Elf_Options for an ODK_HWPATCH entry.  */

#define OHW_R4KEOP	0x1	/* R4000 end-of-page patch.  */
#define OHW_R8KPFETCH	0x2	/* may need R8000 prefetch patch.  */
#define OHW_R5KEOP	0x4	/* R5000 end-of-page patch.  */
#define OHW_R5KCVTL	0x8	/* R5000 cvt.[ds].l bug.  clean=1.  */

#define OPAD_PREFIX	0x1
#define OPAD_POSTFIX	0x2
#define OPAD_SYMBOL	0x4
