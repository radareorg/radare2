/* This file defines standard ELF types, structures, and macros.
   Copyright (C) 1995, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ian Lance Taylor <ian@cygnus.com>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef _ELF_H
#define _ELF_H 1

#ifndef _WIN32
#include <inttypes.h>
#else
#ifndef __int8_t_defined
#define __int8_t_defined
typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef long long int int64_t;
#endif

typedef unsigned char           uint8_t;
typedef unsigned short int      uint16_t;
typedef unsigned int            uint32_t;
typedef unsigned long long int  uint64_t;
#endif

/* Standard ELF types.  */

/* Type for a 16-bit quantity.  */
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

/* Type of symbol indices.  */
typedef uint32_t Elf32_Symndx;
typedef uint64_t Elf64_Symndx;


/* The ELF file header.  This appears at the start of every ELF file.  */

#define EI_NIDENT (16)

typedef struct
{
  unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
  Elf32_Half    e_type;                 /* Object file type */
  Elf32_Half    e_machine;              /* Architecture */
  Elf32_Word    e_version;              /* Object file version */
  Elf32_Addr    e_entry;                /* Entry point virtual address */
  Elf32_Off     e_phoff;                /* Program header table file offset */
  Elf32_Off     e_shoff;                /* Section header table file offset */
  Elf32_Word    e_flags;                /* Processor-specific flags */
  Elf32_Half    e_ehsize;               /* ELF header size in bytes */
  Elf32_Half    e_phentsize;            /* Program header table entry size */
  Elf32_Half    e_phnum;                /* Program header table entry count */
  Elf32_Half    e_shentsize;            /* Section header table entry size */
  Elf32_Half    e_shnum;                /* Section header table entry count */
  Elf32_Half    e_shstrndx;             /* Section header string table index */
} Elf32_Ehdr;

typedef struct
{
  unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
  Elf64_Half    e_type;                 /* Object file type */
  Elf64_Half    e_machine;              /* Architecture */
  Elf64_Word    e_version;              /* Object file version */
  Elf64_Addr    e_entry;                /* Entry point virtual address */
  Elf64_Off     e_phoff;                /* Program header table file offset */
  Elf64_Off     e_shoff;                /* Section header table file offset */
  Elf64_Word    e_flags;                /* Processor-specific flags */
  Elf64_Half    e_ehsize;               /* ELF header size in bytes */
  Elf64_Half    e_phentsize;            /* Program header table entry size */
  Elf64_Half    e_phnum;                /* Program header table entry count */
  Elf64_Half    e_shentsize;            /* Section header table entry size */
  Elf64_Half    e_shnum;                /* Section header table entry count */
  Elf64_Half    e_shstrndx;             /* Section header string table index */
} Elf64_Ehdr;

/* Fields in the e_ident array.  The EI_* macros are indices into the
   array.  The macros under each EI_* macro are the values the byte
   may have.  */

#define EI_MAG0         0               /* File identification byte 0 index */
#define ELFMAG0         0x7f            /* Magic number byte 0 */

#define EI_MAG1         1               /* File identification byte 1 index */
#define ELFMAG1         'E'             /* Magic number byte 1 */

#define EI_MAG2         2               /* File identification byte 2 index */
#define ELFMAG2         'L'             /* Magic number byte 2 */

#define EI_MAG3         3               /* File identification byte 3 index */
#define ELFMAG3         'F'             /* Magic number byte 3 */

/* Conglomeration of the identification bytes, for easy testing as a word.  */
#define ELFMAG          "\177ELF"
#define SELFMAG         4

#define EI_CLASS        4               /* File class byte index */
#define ELFCLASSNONE    0               /* Invalid class */
#define ELFCLASS32      1               /* 32-bit objects */
#define ELFCLASS64      2               /* 64-bit objects */
#define ELFCLASSNUM     3

#define EI_DATA         5               /* Data encoding byte index */
#define ELFDATANONE     0               /* Invalid data encoding */
#define ELFDATA2LSB     1               /* 2's complement, little endian */
#define ELFDATA2MSB     2               /* 2's complement, big endian */
#define ELFDATANUM      3

#define EI_VERSION      6               /* File version byte index */
                                        /* Value must be EV_CURRENT */

#define EI_OSABI        7               /* OS ABI identification */
#define ELFOSABI_SYSV           0       /* UNIX System V ABI */
#define ELFOSABI_HPUX           1       /* HP-UX */
#define ELFOSABI_FREEBSD        9       /* Free BSD */
#define ELFOSABI_ARM            97      /* ARM */
#define ELFOSABI_STANDALONE     255     /* Standalone (embedded) application */

#define EI_ABIVERSION   8               /* ABI version */

#define EI_PAD          9               /* Byte index of padding bytes */

/* Legal values for e_type (object file type).  */

#define ET_NONE         0               /* No file type */
#define ET_REL          1               /* Relocatable file */
#define ET_EXEC         2               /* Executable file */
#define ET_DYN          3               /* Shared object file */
#define ET_CORE         4               /* Core file */
#define ET_NUM          5               /* Number of defined types */
#define ET_LOPROC       0xff00          /* Processor-specific */
#define ET_HIPROC       0xffff          /* Processor-specific */

/* Legal values for e_machine (architecture).  */

#define EM_NONE          0              /* No machine */
#define EM_M32           1              /* AT&T WE 32100 */
#define EM_SPARC         2              /* SUN SPARC */
#define EM_386           3              /* Intel 80386 */
#define EM_68K           4              /* Motorola m68k family */
#define EM_88K           5              /* Motorola m88k family */
#define EM_486           6              /* Intel 80486 */
#define EM_860           7              /* Intel 80860 */
#define EM_MIPS          8              /* MIPS R3000 big-endian */
#define EM_S370          9              /* Amdahl */
#define EM_MIPS_RS4_BE  10              /* MIPS R4000 big-endian */
#define EM_RS6000       11              /* RS6000 */

#define EM_PARISC       15              /* HPPA */
#define EM_nCUBE        16              /* nCUBE */
#define EM_VPP500       17              /* Fujitsu VPP500 */
#define EM_SPARC32PLUS  18              /* Sun's "v8plus" */
#define EM_960          19              /* Intel 80960 */
#define EM_PPC          20              /* PowerPC */

#define EM_V800         36              /* NEC V800 series */
#define EM_FR20         37              /* Fujitsu FR20 */
#define EM_RH32         38              /* TRW RH32 */
#define EM_RCE          39              /* Motorola RCE */
#define EM_ARM          40              /* ARM */
#define EM_FAKE_ALPHA   41              /* Digital Alpha */
#define EM_SH           42              /* Hitachi SH */
#define EM_SPARCV9      43              /* SPARC v9 64-bit */
#define EM_TRICORE      44              /* Siemens Tricore */
#define EM_ARC          45              /* Argonaut RISC Core */
#define EM_H8_300       46              /* Hitachi H8/300 */
#define EM_H8_300H      47              /* Hitachi H8/300H */
#define EM_H8S          48              /* Hitachi H8S */
#define EM_H8_500       49              /* Hitachi H8/500 */
#define EM_IA_64        50              /* Intel Merced */
#define EM_MIPS_X       51              /* Stanford MIPS-X */
#define EM_COLDFIRE     52              /* Motorola Coldfire */
#define EM_68HC12       53              /* Motorola M68HC12 */
#define EM_MMA          54              /* Fujitsu MMA Multimedia Accelerator*/
#define EM_PCP          55              /* Siemens PCP */
#define EM_NCPU         56              /* Sony nCPU embeeded RISC */
#define EM_NDR1         57              /* Denso NDR1 microprocessor */
#define EM_STARCORE     58              /* Motorola Start*Core processor */
#define EM_ME16         59              /* Toyota ME16 processor */
#define EM_ST100        60              /* STMicroelectronic ST100 processor */
#define EM_TINYJ        61              /* Advanced Logic Corp. Tinyj emb.fam*/
#define EM_X86_64       62              /* AMD x86-64 architecture */
#define EM_PDSP         63              /* Sony DSP Processor */
#define EM_FX66         66              /* Siemens FX66 microcontroller */
#define EM_ST9PLUS      67              /* STMicroelectronics ST9+ 8/16 mc */
#define EM_ST7          68              /* STmicroelectronics ST7 8 bit mc */
#define EM_68HC16       69              /* Motorola MC68HC16 microcontroller */
#define EM_68HC11       70              /* Motorola MC68HC11 microcontroller */
#define EM_68HC08       71              /* Motorola MC68HC08 microcontroller */
#define EM_68HC05       72              /* Motorola MC68HC05 microcontroller */
#define EM_SVX          73              /* Silicon Graphics SVx */
#define EM_ST19         74              /* STMicroelectronics ST19 8 bit mc */
#define EM_VAX          75              /* Digital VAX */
#define EM_CRIS         76              /* Axis Communications 32-bit embedded processor */
#define EM_JAVELIN      77              /* Infineon Technologies 32-bit embedded processor */
#define EM_FIREPATH     78              /* Element 14 64-bit DSP Processor */
#define EM_ZSP          79              /* LSI Logic 16-bit DSP Processor */
#define EM_MMIX         80              /* Donald Knuth's educational 64-bit processor */
#define EM_HUANY        81              /* Harvard University machine-independent object files */
#define EM_PRISM        82              /* SiTera Prism */
#define EM_AVR          83              /* Atmel AVR 8-bit microcontroller */
#define EM_FR30         84              /* Fujitsu FR30 */
#define EM_D10V         85              /* Mitsubishi D10V */
#define EM_D30V         86              /* Mitsubishi D30V */
#define EM_V850         87              /* NEC v850 */
#define EM_M32R         88              /* Mitsubishi M32R */
#define EM_MN10300      89              /* Matsushita MN10300 */
#define EM_MN10200      90              /* Matsushita MN10200 */
#define EM_PJ           91              /* picoJava */
#define EM_OPENRISC     92              /* OpenRISC 32-bit embedded processor */
#define EM_ARC_A5       93              /* ARC Cores Tangent-A5 */
#define EM_XTENSA       94              /* Tensilica Xtensa Architecture */
#define EM_NUM          95

/* If it is necessary to assign new unofficial EM_* values, please
   pick large random numbers (0x8523, 0xa7f2, etc.) to minimize the
   chances of collision with official or non-GNU unofficial values.  */

#define EM_ALPHA        0x9026
#define EM_C60          0x9c60

/* Legal values for e_version (version).  */

#define EV_NONE         0               /* Invalid ELF version */
#define EV_CURRENT      1               /* Current version */
#define EV_NUM          2

/* Section header.  */

typedef struct
{
  Elf32_Word    sh_name;                /* Section name (string tbl index) */
  Elf32_Word    sh_type;                /* Section type */
  Elf32_Word    sh_flags;               /* Section flags */
  Elf32_Addr    sh_addr;                /* Section virtual addr at execution */
  Elf32_Off     sh_offset;              /* Section file offset */
  Elf32_Word    sh_size;                /* Section size in bytes */
  Elf32_Word    sh_link;                /* Link to another section */
  Elf32_Word    sh_info;                /* Additional section information */
  Elf32_Word    sh_addralign;           /* Section alignment */
  Elf32_Word    sh_entsize;             /* Entry size if section holds table */
} Elf32_Shdr;

typedef struct
{
  Elf64_Word    sh_name;                /* Section name (string tbl index) */
  Elf64_Word    sh_type;                /* Section type */
  Elf64_Xword   sh_flags;               /* Section flags */
  Elf64_Addr    sh_addr;                /* Section virtual addr at execution */
  Elf64_Off     sh_offset;              /* Section file offset */
  Elf64_Xword   sh_size;                /* Section size in bytes */
  Elf64_Word    sh_link;                /* Link to another section */
  Elf64_Word    sh_info;                /* Additional section information */
  Elf64_Xword   sh_addralign;           /* Section alignment */
  Elf64_Xword   sh_entsize;             /* Entry size if section holds table */
} Elf64_Shdr;

/* Special section indices.  */

#define SHN_UNDEF       0               /* Undefined section */
#define SHN_LORESERVE   0xff00          /* Start of reserved indices */
#define SHN_LOPROC      0xff00          /* Start of processor-specific */
#define SHN_HIPROC      0xff1f          /* End of processor-specific */
#define SHN_ABS         0xfff1          /* Associated symbol is absolute */
#define SHN_COMMON      0xfff2          /* Associated symbol is common */
#define SHN_HIRESERVE   0xffff          /* End of reserved indices */

/* Legal values for sh_type (section type).  */

#define SHT_NULL         0              /* Section header table entry unused */
#define SHT_PROGBITS     1              /* Program data */
#define SHT_SYMTAB       2              /* Symbol table */
#define SHT_STRTAB       3              /* String table */
#define SHT_RELA         4              /* Relocation entries with addends */
#define SHT_HASH         5              /* Symbol hash table */
#define SHT_DYNAMIC      6              /* Dynamic linking information */
#define SHT_NOTE         7              /* Notes */
#define SHT_NOBITS       8              /* Program space with no data (bss) */
#define SHT_REL          9              /* Relocation entries, no addends */
#define SHT_SHLIB        10             /* Reserved */
#define SHT_DYNSYM       11             /* Dynamic linker symbol table */
#define SHT_INIT_ARRAY   14             /* Array of constructors */
#define SHT_FINI_ARRAY   15             /* Array of destructors */
#define SHT_PREINIT_ARRAY 16            /* Array of pre-constructors */
#define SHT_GROUP        17             /* Section group */
#define SHT_SYMTAB_SHNDX 18             /* Extended section indices */
#define SHT_NUM          19             /* Number of defined types.  */
#define SHT_LOOS         0x60000000     /* Start OS-specific */
#define SHT_LOSUNW       0x6ffffffb     /* Sun-specific low bound.  */
#define SHT_SUNW_COMDAT  0x6ffffffb
#define SHT_SUNW_syminfo 0x6ffffffc
#define SHT_GNU_verdef   0x6ffffffd     /* Version definition section.  */
#define SHT_GNU_verneed  0x6ffffffe     /* Version needs section.  */
#define SHT_GNU_versym   0x6fffffff     /* Version symbol table.  */
#define SHT_HISUNW       0x6fffffff     /* Sun-specific high bound.  */
#define SHT_HIOS         0x6fffffff     /* End OS-specific type */
#define SHT_LOPROC       0x70000000     /* Start of processor-specific */
#define SHT_ARM_EXIDX    0x70000001     /* Exception Index table */
#define SHT_ARM_PREEMPTMAP 0x70000002   /* dynamic linking pre-emption map */
#define SHT_ARM_ATTRIBUTES 0x70000003   /* Object file compatibility attrs */
#define SHT_HIPROC       0x7fffffff     /* End of processor-specific */
#define SHT_LOUSER       0x80000000     /* Start of application-specific */
#define SHT_HIUSER       0x8fffffff     /* End of application-specific */

/* Legal values for sh_flags (section flags).  */

#define SHF_WRITE       (1 << 0)        /* Writable */
#define SHF_ALLOC       (1 << 1)        /* Occupies memory during execution */
#define SHF_EXECINSTR   (1 << 2)        /* Executable */
#define SHF_MASKPROC    0xf0000000      /* Processor-specific */

#define SHF_MERGE       0x10
#define SHF_STRINGS     0x20
#define SHF_INFO_LINK   0x40
#define SHF_LINK_ORDER  0x80
#define SHF_OS_NONCONFORMING 0x100
#define SHF_GROUP       0x200
#define SHF_TLS         0x400
#define SHF_MASKOS      0x0ff00000
#define SHF_ORDERED     0x40000000
#define SHF_EXCLUDE     0x80000000

/* Symbol table entry.  */

typedef struct
{
  Elf32_Word    st_name;                /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;               /* Symbol value */
  Elf32_Word    st_size;                /* Symbol size */
  unsigned char st_info;                /* Symbol type and binding */
  unsigned char st_other;               /* No defined meaning, 0 */
  Elf32_Section st_shndx;               /* Section index */
} Elf32_Sym;

typedef struct
{
  Elf64_Word    st_name;                /* Symbol name (string tbl index) */
  unsigned char st_info;                /* Symbol type and binding */
  unsigned char st_other;               /* No defined meaning, 0 */
  Elf64_Section st_shndx;               /* Section index */
  Elf64_Addr    st_value;               /* Symbol value */
  Elf64_Xword   st_size;                /* Symbol size */
} Elf64_Sym;

/* The syminfo section if available contains additional information about
   every dynamic symbol.  */

typedef struct
{
  Elf32_Half si_boundto;                /* Direct bindings, symbol bound to */
  Elf32_Half si_flags;                  /* Per symbol flags */
} Elf32_Syminfo;

typedef struct
{
  Elf64_Half si_boundto;                /* Direct bindings, symbol bound to */
  Elf64_Half si_flags;                  /* Per symbol flags */
} Elf64_Syminfo;

/* Possible values for si_boundto.  */
#define SYMINFO_BT_SELF         0xffff  /* Symbol bound to self */
#define SYMINFO_BT_PARENT       0xfffe  /* Symbol bound to parent */
#define SYMINFO_BT_LOWRESERVE   0xff00  /* Beginning of reserved entries */

/* Possible bitmasks for si_flags.  */
#define SYMINFO_FLG_DIRECT      0x0001  /* Direct bound symbol */
#define SYMINFO_FLG_PASSTHRU    0x0002  /* Pass-thru symbol for translator */
#define SYMINFO_FLG_COPY        0x0004  /* Symbol is a copy-reloc */
#define SYMINFO_FLG_LAZYLOAD    0x0008  /* Symbol bound to object to be lazy
                                           loaded */
/* Syminfo version values.  */
#define SYMINFO_NONE            0
#define SYMINFO_CURRENT         1
#define SYMINFO_NUM             2


/* Special section index.  */

#define SHN_UNDEF       0               /* No section, undefined symbol.  */

/* How to extract and insert information held in the st_info field.  */

#define ELF32_ST_BIND(val)              (((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val)              ((val) & 0xf)
#define ELF32_ST_INFO(bind, type)       (((bind) << 4) + ((type) & 0xf))

/* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
#define ELF64_ST_BIND(val)              ELF32_ST_BIND (val)
#define ELF64_ST_TYPE(val)              ELF32_ST_TYPE (val)
#define ELF64_ST_INFO(bind, type)       ELF32_ST_INFO ((bind), (type))

/* Legal values for ST_BIND subfield of st_info (symbol binding).  */

#define STB_LOCAL       0               /* Local symbol */
#define STB_GLOBAL      1               /* Global symbol */
#define STB_WEAK        2               /* Weak symbol */
#define STB_NUM         3               /* Number of defined types.  */
#define STB_LOOS        10              /* Start of OS-specific */
#define STB_HIOS        12              /* End of OS-specific */
#define STB_LOPROC      13              /* Start of processor-specific */
#define STB_HIPROC      15              /* End of processor-specific */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_NOTYPE      0               /* Symbol type is unspecified */
#define STT_OBJECT      1               /* Symbol is a data object */
#define STT_FUNC        2               /* Symbol is a code object */
#define STT_SECTION     3               /* Symbol associated with a section */
#define STT_FILE        4               /* Symbol's name is file name */
#define STT_NUM         5               /* Number of defined types.  */
#define STT_GNU_IFUNC   10              /* Symbol is a indirect code object */
#define STT_LOOS        11              /* Start of OS-specific */
#define STT_HIOS        12              /* End of OS-specific */
#define STT_LOPROC      13              /* Start of processor-specific */
#define STT_HIPROC      15              /* End of processor-specific */


/* Symbol table indices are found in the hash buckets and chain table
   of a symbol hash table section.  This special index value indicates
   the end of a chain, meaning no further symbols are found in that bucket.  */

#define STN_UNDEF       0               /* End of a chain.  */


/* How to extract and insert information held in the st_other field.  */

#define ELF32_ST_VISIBILITY(o)  ((o) & 0x03)

/* For ELF64 the definitions are the same.  */
#define ELF64_ST_VISIBILITY(o)  ELF32_ST_VISIBILITY (o)

/* Symbol visibility specification encoded in the st_other field.  */
#define STV_DEFAULT     0               /* Default symbol visibility rules */
#define STV_INTERNAL    1               /* Processor specific hidden class */
#define STV_HIDDEN      2               /* Sym unavailable in other modules */
#define STV_PROTECTED   3               /* Not preemptible, not exported */


/* Relocation table entry without addend (in section of type SHT_REL).  */

typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;

/* I have seen two different definitions of the Elf64_Rel and
   Elf64_Rela structures, so we'll leave them out until Novell (or
   whoever) gets their act together.  */
/* The following, at least, is used on Sparc v9, MIPS, and Alpha.  */

typedef struct
{
  Elf64_Addr    r_offset;               /* Address */
  Elf64_Xword   r_info;                 /* Relocation type and symbol index */
} Elf64_Rel;

/* Relocation table entry with addend (in section of type SHT_RELA).  */

typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
  Elf32_Sword   r_addend;               /* Addend */
} Elf32_Rela;

typedef struct
{
  Elf64_Addr    r_offset;               /* Address */
  Elf64_Xword   r_info;                 /* Relocation type and symbol index */
  Elf64_Sxword  r_addend;               /* Addend */
} Elf64_Rela;

/* How to extract and insert information held in the r_info field.  */

#define ELF32_R_SYM(val)                ((val) >> 8)
#define ELF32_R_TYPE(val)               ((val) & 0xff)
#define ELF32_R_INFO(sym, type)         (((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)                  ((i) >> 32)
#define ELF64_R_TYPE(i)                 ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)          ((((Elf64_Xword)(sym)) << 32) + (type))

/* Program segment header.  */

typedef struct
{
  Elf32_Word    p_type;                 /* Segment type */
  Elf32_Off     p_offset;               /* Segment file offset */
  Elf32_Addr    p_vaddr;                /* Segment virtual address */
  Elf32_Addr    p_paddr;                /* Segment physical address */
  Elf32_Word    p_filesz;               /* Segment size in file */
  Elf32_Word    p_memsz;                /* Segment size in memory */
  Elf32_Word    p_flags;                /* Segment flags */
  Elf32_Word    p_align;                /* Segment alignment */
} Elf32_Phdr;

typedef struct
{
  Elf64_Word    p_type;                 /* Segment type */
  Elf64_Word    p_flags;                /* Segment flags */
  Elf64_Off     p_offset;               /* Segment file offset */
  Elf64_Addr    p_vaddr;                /* Segment virtual address */
  Elf64_Addr    p_paddr;                /* Segment physical address */
  Elf64_Xword   p_filesz;               /* Segment size in file */
  Elf64_Xword   p_memsz;                /* Segment size in memory */
  Elf64_Xword   p_align;                /* Segment alignment */
} Elf64_Phdr;

/* Legal values for p_type (segment type).  */

#define PT_NULL         0               /* Program header table entry unused */
#define PT_LOAD         1               /* Loadable program segment */
#define PT_DYNAMIC      2               /* Dynamic linking information */
#define PT_INTERP       3               /* Program interpreter */
#define PT_NOTE         4               /* Auxiliary information */
#define PT_SHLIB        5               /* Reserved */
#define PT_PHDR         6               /* Entry for header table itself */
#define PT_NUM          7               /* Number of defined types.  */
#define PT_LOOS         0x60000000      /* Start of OS-specific */
#define PT_HIOS         0x6fffffff      /* End of OS-specific */
#define PT_LOPROC       0x70000000      /* Start of processor-specific */
#define PT_HIPROC       0x7fffffff      /* End of processor-specific */

/* Legal values for p_flags (segment flags).  */

#define PF_X            (1 << 0)        /* Segment is executable */
#define PF_W            (1 << 1)        /* Segment is writable */
#define PF_R            (1 << 2)        /* Segment is readable */
#define PF_MASKPROC     0xf0000000      /* Processor-specific */

/* Legal values for note segment descriptor types for core files. */

#define NT_PRSTATUS     1               /* Contains copy of prstatus struct */
#define NT_FPREGSET     2               /* Contains copy of fpregset struct */
#define NT_PRPSINFO     3               /* Contains copy of prpsinfo struct */
#define NT_PRXREG       4               /* Contains copy of prxregset struct */
#define NT_PLATFORM     5               /* String from sysinfo(SI_PLATFORM) */
#define NT_AUXV         6               /* Contains copy of auxv array */
#define NT_GWINDOWS     7               /* Contains copy of gwindows struct */
#define NT_PSTATUS      10              /* Contains copy of pstatus struct */
#define NT_PSINFO       13              /* Contains copy of psinfo struct */
#define NT_PRCRED       14              /* Contains copy of prcred struct */
#define NT_UTSNAME      15              /* Contains copy of utsname struct */
#define NT_LWPSTATUS    16              /* Contains copy of lwpstatus struct */
#define NT_LWPSINFO     17              /* Contains copy of lwpinfo struct */

/* Legal values for the  note segment descriptor types for object files.  */

#define NT_VERSION      1               /* Contains a version string.  */


/* Dynamic section entry.  */

typedef struct
{
  Elf32_Sword   d_tag;                  /* Dynamic entry type */
  union
    {
      Elf32_Word d_val;                 /* Integer value */
      Elf32_Addr d_ptr;                 /* Address value */
    } d_un;
} Elf32_Dyn;

typedef struct
{
  Elf64_Sxword  d_tag;                  /* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;                /* Integer value */
      Elf64_Addr d_ptr;                 /* Address value */
    } d_un;
} Elf64_Dyn;

/* Legal values for d_tag (dynamic entry type).  */

#define DT_NULL         0               /* Marks end of dynamic section */
#define DT_NEEDED       1               /* Name of needed library */
#define DT_PLTRELSZ     2               /* Size in bytes of PLT relocs */
#define DT_PLTGOT       3               /* Processor defined value */
#define DT_HASH         4               /* Address of symbol hash table */
#define DT_STRTAB       5               /* Address of string table */
#define DT_SYMTAB       6               /* Address of symbol table */
#define DT_RELA         7               /* Address of Rela relocs */
#define DT_RELASZ       8               /* Total size of Rela relocs */
#define DT_RELAENT      9               /* Size of one Rela reloc */
#define DT_STRSZ        10              /* Size of string table */
#define DT_SYMENT       11              /* Size of one symbol table entry */
#define DT_INIT         12              /* Address of init function */
#define DT_FINI         13              /* Address of termination function */
#define DT_SONAME       14              /* Name of shared object */
#define DT_RPATH        15              /* Library search path */
#define DT_SYMBOLIC     16              /* Start symbol search here */
#define DT_REL          17              /* Address of Rel relocs */
#define DT_RELSZ        18              /* Total size of Rel relocs */
#define DT_RELENT       19              /* Size of one Rel reloc */
#define DT_PLTREL       20              /* Type of reloc in PLT */
#define DT_DEBUG        21              /* For debugging; unspecified */
#define DT_TEXTREL      22              /* Reloc might modify .text */
#define DT_JMPREL       23              /* Address of PLT relocs */
#define DT_BIND_NOW     24              /* Process relocations of object */
#define DT_INIT_ARRAY   25              /* Array with addresses of init fct */
#define DT_FINI_ARRAY   26              /* Array with addresses of fini fct */
#define DT_INIT_ARRAYSZ 27              /* Size in bytes of DT_INIT_ARRAY */
#define DT_FINI_ARRAYSZ 28              /* Size in bytes of DT_FINI_ARRAY */
#define DT_NUM          29              /* Number used */
#define DT_LOOS         0x60000000      /* Start of OS-specific */
#define DT_HIOS         0x6fffffff      /* End of OS-specific */
#define DT_LOPROC       0x70000000      /* Start of processor-specific */
#define DT_HIPROC       0x7fffffff      /* End of processor-specific */
#define DT_PROCNUM      DT_MIPS_NUM     /* Most used by any processor */

/* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
   Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
   approach.  */
#define DT_VALRNGLO     0x6ffffd00
#define DT_POSFLAG_1    0x6ffffdfd      /* Flags for DT_* entries, effecting
                                           the following DT_* entry.  */
#define DT_SYMINSZ      0x6ffffdfe      /* Size of syminfo table (in bytes) */
#define DT_SYMINENT     0x6ffffdff      /* Entry size of syminfo */
#define DT_VALRNGHI     0x6ffffdff

/* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
   Dyn.d_un.d_ptr field of the Elf*_Dyn structure.

   If any adjustment is made to the ELF object after it has been
   built these entries will need to be adjusted.  */
#define DT_ADDRRNGLO    0x6ffffe00
#define DT_SYMINFO      0x6ffffeff      /* syminfo table */
#define DT_ADDRRNGHI    0x6ffffeff

/* The versioning entry types.  The next are defined as part of the
   GNU extension.  */
#define DT_VERSYM       0x6ffffff0

/* These were chosen by Sun.  */
#define DT_FLAGS_1      0x6ffffffb      /* State flags, see DF_1_* below.  */
#define DT_VERDEF       0x6ffffffc      /* Address of version definition
                                           table */
#define DT_VERDEFNUM    0x6ffffffd      /* Number of version definitions */
#define DT_VERNEED      0x6ffffffe      /* Address of table with needed
                                           versions */
#define DT_VERNEEDNUM   0x6fffffff      /* Number of needed versions */
#define DT_VERSIONTAGIDX(tag)   (DT_VERNEEDNUM - (tag)) /* Reverse order! */
#define DT_VERSIONTAGNUM 16

/* Sun added these machine-independent extensions in the "processor-specific"
   range.  Be compatible.  */
#define DT_AUXILIARY    0x7ffffffd      /* Shared object to load before self */
#define DT_FILTER       0x7fffffff      /* Shared object to get values from */
#define DT_EXTRATAGIDX(tag)     ((Elf32_Word)-((Elf32_Sword) (tag) <<1>>1)-1)
#define DT_EXTRANUM     3

/* State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
   entry in the dynamic section.  */
#define DF_1_NOW        0x00000001      /* Set RTLD_NOW for this object.  */
#define DF_1_GLOBAL     0x00000002      /* Set RTLD_GLOBAL for this object.  */
#define DF_1_GROUP      0x00000004      /* Set RTLD_GROUP for this object.  */
#define DF_1_NODELETE   0x00000008      /* Set RTLD_NODELETE for this object.*/
#define DF_1_LOADFLTR   0x00000010      /* Trigger filtee loading at runtime.*/
#define DF_1_INITFIRST  0x00000020      /* Set RTLD_INITFIRST for this object*/
#define DF_1_NOOPEN     0x00000040      /* Set RTLD_NOOPEN for this object.  */

/* Version definition sections.  */

typedef struct
{
  Elf32_Half    vd_version;             /* Version revision */
  Elf32_Half    vd_flags;               /* Version information */
  Elf32_Half    vd_ndx;                 /* Version Index */
  Elf32_Half    vd_cnt;                 /* Number of associated aux entries */
  Elf32_Word    vd_hash;                /* Version name hash value */
  Elf32_Word    vd_aux;                 /* Offset in bytes to verdaux array */
  Elf32_Word    vd_next;                /* Offset in bytes to next verdef
                                           entry */
} Elf32_Verdef;

typedef struct
{
  Elf64_Half    vd_version;             /* Version revision */
  Elf64_Half    vd_flags;               /* Version information */
  Elf64_Half    vd_ndx;                 /* Version Index */
  Elf64_Half    vd_cnt;                 /* Number of associated aux entries */
  Elf64_Word    vd_hash;                /* Version name hash value */
  Elf64_Word    vd_aux;                 /* Offset in bytes to verdaux array */
  Elf64_Word    vd_next;                /* Offset in bytes to next verdef
                                           entry */
} Elf64_Verdef;


/* Legal values for vd_version (version revision).  */
#define VER_DEF_NONE    0               /* No version */
#define VER_DEF_CURRENT 1               /* Current version */
#define VER_DEF_NUM     2               /* Given version number */

/* Legal values for vd_flags (version information flags).  */
#define VER_FLG_BASE    0x1             /* Version definition of file itself */
#define VER_FLG_WEAK    0x2             /* Weak version identifier */

/* Auxialiary version information.  */

typedef struct
{
  Elf32_Word    vda_name;               /* Version or dependency names */
  Elf32_Word    vda_next;               /* Offset in bytes to next verdaux
                                           entry */
} Elf32_Verdaux;

typedef struct
{
  Elf64_Word    vda_name;               /* Version or dependency names */
  Elf64_Word    vda_next;               /* Offset in bytes to next verdaux
                                           entry */
} Elf64_Verdaux;


/* Version dependency section.  */

typedef struct
{
  Elf32_Half    vn_version;             /* Version of structure */
  Elf32_Half    vn_cnt;                 /* Number of associated aux entries */
  Elf32_Word    vn_file;                /* Offset of filename for this
                                           dependency */
  Elf32_Word    vn_aux;                 /* Offset in bytes to vernaux array */
  Elf32_Word    vn_next;                /* Offset in bytes to next verneed
                                           entry */
} Elf32_Verneed;

typedef struct
{
  Elf64_Half    vn_version;             /* Version of structure */
  Elf64_Half    vn_cnt;                 /* Number of associated aux entries */
  Elf64_Word    vn_file;                /* Offset of filename for this
                                           dependency */
  Elf64_Word    vn_aux;                 /* Offset in bytes to vernaux array */
  Elf64_Word    vn_next;                /* Offset in bytes to next verneed
                                           entry */
} Elf64_Verneed;


/* Legal values for vn_version (version revision).  */
#define VER_NEED_NONE    0              /* No version */
#define VER_NEED_CURRENT 1              /* Current version */
#define VER_NEED_NUM     2              /* Given version number */

/* Auxiliary needed version information.  */

typedef struct
{
  Elf32_Word    vna_hash;               /* Hash value of dependency name */
  Elf32_Half    vna_flags;              /* Dependency specific information */
  Elf32_Half    vna_other;              /* Unused */
  Elf32_Word    vna_name;               /* Dependency name string offset */
  Elf32_Word    vna_next;               /* Offset in bytes to next vernaux
                                           entry */
} Elf32_Vernaux;

typedef struct
{
  Elf64_Word    vna_hash;               /* Hash value of dependency name */
  Elf64_Half    vna_flags;              /* Dependency specific information */
  Elf64_Half    vna_other;              /* Unused */
  Elf64_Word    vna_name;               /* Dependency name string offset */
  Elf64_Word    vna_next;               /* Offset in bytes to next vernaux
                                           entry */
} Elf64_Vernaux;


/* Legal values for vna_flags.  */
#define VER_FLG_WEAK    0x2             /* Weak version identifier */


/* Auxiliary vector.  */

/* This vector is normally only used by the program interpreter.  The
   usual definition in an ABI supplement uses the name auxv_t.  The
   vector is not usually defined in a standard <elf.h> file, but it
   can't hurt.  We rename it to avoid conflicts.  The sizes of these
   types are an arrangement between the exec server and the program
   interpreter, so we don't fully specify them here.  */

typedef struct
{
  int a_type;                   /* Entry type */
  union
    {
      long int a_val;           /* Integer value */
      void *a_ptr;              /* Pointer value */
      void (*a_fcn) (void);     /* Function pointer value */
    } a_un;
} Elf32_auxv_t;

typedef struct
{
  long int a_type;              /* Entry type */
  union
    {
      long int a_val;           /* Integer value */
      void *a_ptr;              /* Pointer value */
      void (*a_fcn) (void);     /* Function pointer value */
    } a_un;
} Elf64_auxv_t;

/* Legal values for a_type (entry type).  */

#define AT_NULL         0               /* End of vector */
#define AT_IGNORE       1               /* Entry should be ignored */
#define AT_EXECFD       2               /* File descriptor of program */
#define AT_PHDR         3               /* Program headers for program */
#define AT_PHENT        4               /* Size of program header entry */
#define AT_PHNUM        5               /* Number of program headers */
#define AT_PAGESZ       6               /* System page size */
#define AT_BASE         7               /* Base address of interpreter */
#define AT_FLAGS        8               /* Flags */
#define AT_ENTRY        9               /* Entry point of program */
#define AT_NOTELF       10              /* Program is not ELF */
#define AT_UID          11              /* Real uid */
#define AT_EUID         12              /* Effective uid */
#define AT_GID          13              /* Real gid */
#define AT_EGID         14              /* Effective gid */

/* Some more special a_type values describing the hardware.  */
#define AT_PLATFORM     15              /* String identifying platform.  */
#define AT_HWCAP        16              /* Machine dependent hints about
                                           processor capabilities.  */

/* This entry gives some information about the FPU initialization
   performed by the kernel.  */
#define AT_FPUCW        17              /* Used FPU control word.  */


/* Note section contents.  Each entry in the note section begins with
   a header of a fixed form.  */

typedef struct
{
  Elf32_Word n_namesz;                  /* Length of the note's name.  */
  Elf32_Word n_descsz;                  /* Length of the note's descriptor.  */
  Elf32_Word n_type;                    /* Type of the note.  */
} Elf32_Nhdr;

typedef struct
{
  Elf64_Word n_namesz;                  /* Length of the note's name.  */
  Elf64_Word n_descsz;                  /* Length of the note's descriptor.  */
  Elf64_Word n_type;                    /* Type of the note.  */
} Elf64_Nhdr;

/* Known names of notes.  */

/* Solaris entries in the note section have this name.  */
#define ELF_NOTE_SOLARIS        "SUNW Solaris"

/* Note entries for GNU systems have this name.  */
#define ELF_NOTE_GNU            "GNU"


/* Defined types of notes for Solaris.  */

/* Value of descriptor (one word) is desired pagesize for the binary.  */
#define ELF_NOTE_PAGESIZE_HINT  1


/* Defined note types for GNU systems.  */

/* ABI information.  The descriptor consists of words:
   word 0: OS descriptor
   word 1: major version of the ABI
   word 2: minor version of the ABI
   word 3: subminor version of the ABI
*/
#define ELF_NOTE_ABI            1

/* Known OSes.  These value can appear in word 0 of an ELF_NOTE_ABI
   note section entry.  */
#define ELF_NOTE_OS_LINUX       0
#define ELF_NOTE_OS_GNU         1
#define ELF_NOTE_OS_SOLARIS2    2


/* Motorola 68k specific definitions.  */

/* m68k relocs.  */

#define R_68K_NONE      0               /* No reloc */
#define R_68K_32        1               /* Direct 32 bit  */
#define R_68K_16        2               /* Direct 16 bit  */
#define R_68K_8         3               /* Direct 8 bit  */
#define R_68K_PC32      4               /* PC relative 32 bit */
#define R_68K_PC16      5               /* PC relative 16 bit */
#define R_68K_PC8       6               /* PC relative 8 bit */
#define R_68K_GOT32     7               /* 32 bit PC relative GOT entry */
#define R_68K_GOT16     8               /* 16 bit PC relative GOT entry */
#define R_68K_GOT8      9               /* 8 bit PC relative GOT entry */
#define R_68K_GOT32O    10              /* 32 bit GOT offset */
#define R_68K_GOT16O    11              /* 16 bit GOT offset */
#define R_68K_GOT8O     12              /* 8 bit GOT offset */
#define R_68K_PLT32     13              /* 32 bit PC relative PLT address */
#define R_68K_PLT16     14              /* 16 bit PC relative PLT address */
#define R_68K_PLT8      15              /* 8 bit PC relative PLT address */
#define R_68K_PLT32O    16              /* 32 bit PLT offset */
#define R_68K_PLT16O    17              /* 16 bit PLT offset */
#define R_68K_PLT8O     18              /* 8 bit PLT offset */
#define R_68K_COPY      19              /* Copy symbol at runtime */
#define R_68K_GLOB_DAT  20              /* Create GOT entry */
#define R_68K_JMP_SLOT  21              /* Create PLT entry */
#define R_68K_RELATIVE  22              /* Adjust by program base */
/* Keep this the last entry.  */
#define R_68K_NUM       23

/* Intel 80386 specific definitions.  */

/* i386 relocs.  */

#define R_386_NONE      0               /* No reloc */
#define R_386_32        1               /* Direct 32 bit  */
#define R_386_PC32      2               /* PC relative 32 bit */
#define R_386_GOT32     3               /* 32 bit GOT entry */
#define R_386_PLT32     4               /* 32 bit PLT address */
#define R_386_COPY      5               /* Copy symbol at runtime */
#define R_386_GLOB_DAT  6               /* Create GOT entry */
#define R_386_JMP_SLOT  7               /* Create PLT entry */
#define R_386_RELATIVE  8               /* Adjust by program base */
#define R_386_GOTOFF    9               /* 32 bit offset to GOT */
#define R_386_GOTPC     10              /* 32 bit PC relative offset to GOT */
/* Keep this the last entry.  */
#define R_386_NUM       11

/* TCC-specific 16-bit relocs. */
#define R_386_16        12              /* Direct 16 bit  */
#define R_386_PC16      13              /* PC relative 16 bit */

/* SUN SPARC specific definitions.  */

/* Values for Elf64_Ehdr.e_flags.  */

#define EF_SPARCV9_MM           3
#define EF_SPARCV9_TSO          0
#define EF_SPARCV9_PSO          1
#define EF_SPARCV9_RMO          2
#define EF_SPARC_EXT_MASK       0xFFFF00
#define EF_SPARC_SUN_US1        0x000200
#define EF_SPARC_HAL_R1         0x000400

/* SPARC relocs.  */

#define R_SPARC_NONE    0               /* No reloc */
#define R_SPARC_8       1               /* Direct 8 bit */
#define R_SPARC_16      2               /* Direct 16 bit */
#define R_SPARC_32      3               /* Direct 32 bit */
#define R_SPARC_DISP8   4               /* PC relative 8 bit */
#define R_SPARC_DISP16  5               /* PC relative 16 bit */
#define R_SPARC_DISP32  6               /* PC relative 32 bit */
#define R_SPARC_WDISP30 7               /* PC relative 30 bit shifted */
#define R_SPARC_WDISP22 8               /* PC relative 22 bit shifted */
#define R_SPARC_HI22    9               /* High 22 bit */
#define R_SPARC_22      10              /* Direct 22 bit */
#define R_SPARC_13      11              /* Direct 13 bit */
#define R_SPARC_LO10    12              /* Truncated 10 bit */
#define R_SPARC_GOT10   13              /* Truncated 10 bit GOT entry */
#define R_SPARC_GOT13   14              /* 13 bit GOT entry */
#define R_SPARC_GOT22   15              /* 22 bit GOT entry shifted */
#define R_SPARC_PC10    16              /* PC relative 10 bit truncated */
#define R_SPARC_PC22    17              /* PC relative 22 bit shifted */
#define R_SPARC_WPLT30  18              /* 30 bit PC relative PLT address */
#define R_SPARC_COPY    19              /* Copy symbol at runtime */
#define R_SPARC_GLOB_DAT 20             /* Create GOT entry */
#define R_SPARC_JMP_SLOT 21             /* Create PLT entry */
#define R_SPARC_RELATIVE 22             /* Adjust by program base */
#define R_SPARC_UA32    23              /* Direct 32 bit unaligned */

/* Additional Sparc64 relocs.  */

#define R_SPARC_PLT32   24              /* Direct 32 bit ref to PLT entry */
#define R_SPARC_HIPLT22 25              /* High 22 bit PLT entry */
#define R_SPARC_LOPLT10 26              /* Truncated 10 bit PLT entry */
#define R_SPARC_PCPLT32 27              /* PC rel 32 bit ref to PLT entry */
#define R_SPARC_PCPLT22 28              /* PC rel high 22 bit PLT entry */
#define R_SPARC_PCPLT10 29              /* PC rel trunc 10 bit PLT entry */
#define R_SPARC_10      30              /* Direct 10 bit */
#define R_SPARC_11      31              /* Direct 11 bit */
#define R_SPARC_64      32              /* Direct 64 bit */
#define R_SPARC_OLO10   33              /* ?? */
#define R_SPARC_HH22    34              /* Top 22 bits of direct 64 bit */
#define R_SPARC_HM10    35              /* High middle 10 bits of ... */
#define R_SPARC_LM22    36              /* Low middle 22 bits of ... */
#define R_SPARC_PC_HH22 37              /* Top 22 bits of pc rel 64 bit */
#define R_SPARC_PC_HM10 38              /* High middle 10 bit of ... */
#define R_SPARC_PC_LM22 39              /* Low miggle 22 bits of ... */
#define R_SPARC_WDISP16 40              /* PC relative 16 bit shifted */
#define R_SPARC_WDISP19 41              /* PC relative 19 bit shifted */
#define R_SPARC_7       43              /* Direct 7 bit */
#define R_SPARC_5       44              /* Direct 5 bit */
#define R_SPARC_6       45              /* Direct 6 bit */
#define R_SPARC_DISP64  46              /* PC relative 64 bit */
#define R_SPARC_PLT64   47              /* Direct 64 bit ref to PLT entry */
#define R_SPARC_HIX22   48              /* High 22 bit complemented */
#define R_SPARC_LOX10   49              /* Truncated 11 bit complemented */
#define R_SPARC_H44     50              /* Direct high 12 of 44 bit */
#define R_SPARC_M44     51              /* Direct mid 22 of 44 bit */
#define R_SPARC_L44     52              /* Direct low 10 of 44 bit */
#define R_SPARC_REGISTER 53             /* Global register usage */
#define R_SPARC_UA64    54              /* Direct 64 bit unaligned */
#define R_SPARC_UA16    55              /* Direct 16 bit unaligned */
/* Keep this the last entry.  */
#define R_SPARC_NUM     56

/* AMD x86-64 relocations.  */
#define R_X86_64_NONE		0	/* No reloc */
#define R_X86_64_64		1	/* Direct 64 bit  */
#define R_X86_64_PC32		2	/* PC relative 32 bit signed */
#define R_X86_64_GOT32		3	/* 32 bit GOT entry */
#define R_X86_64_PLT32		4	/* 32 bit PLT address */
#define R_X86_64_COPY		5	/* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT	6	/* Create GOT entry */
#define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
#define R_X86_64_RELATIVE	8	/* Adjust by program base */
#define R_X86_64_GOTPCREL	9	/* 32 bit signed PC relative
					   offset to GOT */
#define R_X86_64_32		10	/* Direct 32 bit zero extended */
#define R_X86_64_32S		11	/* Direct 32 bit sign extended */
#define R_X86_64_16		12	/* Direct 16 bit zero extended */
#define R_X86_64_PC16		13	/* 16 bit sign extended pc relative */
#define R_X86_64_8		14	/* Direct 8 bit sign extended  */
#define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
#define R_X86_64_DTPMOD64	16	/* ID of module containing symbol */
#define R_X86_64_DTPOFF64	17	/* Offset in module's TLS block */
#define R_X86_64_TPOFF64	18	/* Offset in initial TLS block */
#define R_X86_64_TLSGD		19	/* 32 bit signed PC relative offset
					   to two GOT entries for GD symbol */
#define R_X86_64_TLSLD		20	/* 32 bit signed PC relative offset
					   to two GOT entries for LD symbol */
#define R_X86_64_DTPOFF32	21	/* Offset in TLS block */
#define R_X86_64_GOTTPOFF	22	/* 32 bit signed PC relative offset
					   to GOT entry for IE symbol */
#define R_X86_64_TPOFF32	23	/* Offset in initial TLS block */

#define R_X86_64_NUM		24

/* For Sparc64, legal values for d_tag of Elf64_Dyn.  */

#define DT_SPARC_REGISTER 0x70000001
#define DT_SPARC_NUM    2

/* Bits present in AT_HWCAP, primarily for Sparc32.  */

#define HWCAP_SPARC_FLUSH       1       /* The cpu supports flush insn.  */
#define HWCAP_SPARC_STBAR       2
#define HWCAP_SPARC_SWAP        4
#define HWCAP_SPARC_MULDIV      8
#define HWCAP_SPARC_V9          16      /* The cpu is v9, so v8plus is ok.  */

/* MIPS R3000 specific definitions.  */

/* Legal values for e_flags field of Elf32_Ehdr.  */

#define EF_MIPS_NOREORDER   1           /* A .noreorder directive was used */
#define EF_MIPS_PIC         2           /* Contains PIC code */
#define EF_MIPS_CPIC        4           /* Uses PIC calling sequence */
#define EF_MIPS_XGOT        8
#define EF_MIPS_64BIT_WHIRL 16
#define EF_MIPS_ABI2        32
#define EF_MIPS_ABI_ON32    64
#define EF_MIPS_ARCH        0xf0000000  /* MIPS architecture level */

/* Legal values for MIPS architecture level.  */

#define EF_MIPS_ARCH_1      0x00000000  /* -mips1 code.  */
#define EF_MIPS_ARCH_2      0x10000000  /* -mips2 code.  */
#define EF_MIPS_ARCH_3      0x20000000  /* -mips3 code.  */
#define EF_MIPS_ARCH_4      0x30000000  /* -mips4 code.  */
#define EF_MIPS_ARCH_5      0x40000000  /* -mips5 code.  */

/* The following are non-official names and should not be used.  */

#define E_MIPS_ARCH_1     0x00000000    /* -mips1 code.  */
#define E_MIPS_ARCH_2     0x10000000    /* -mips2 code.  */
#define E_MIPS_ARCH_3     0x20000000    /* -mips3 code.  */
#define E_MIPS_ARCH_4     0x30000000    /* -mips4 code.  */
#define E_MIPS_ARCH_5     0x40000000    /* -mips5 code.  */

/* Special section indices.  */

#define SHN_MIPS_ACOMMON 0xff00         /* Allocated common symbols */
#define SHN_MIPS_TEXT    0xff01         /* Allocated test symbols.  */
#define SHN_MIPS_DATA    0xff02         /* Allocated data symbols.  */
#define SHN_MIPS_SCOMMON 0xff03         /* Small common symbols */
#define SHN_MIPS_SUNDEFINED 0xff04      /* Small undefined symbols */

/* Legal values for sh_type field of Elf32_Shdr.  */

#define SHT_MIPS_LIBLIST       0x70000000 /* Shared objects used in link */
#define SHT_MIPS_MSYM          0x70000001
#define SHT_MIPS_CONFLICT      0x70000002 /* Conflicting symbols */
#define SHT_MIPS_GPTAB         0x70000003 /* Global data area sizes */
#define SHT_MIPS_UCODE         0x70000004 /* Reserved for SGI/MIPS compilers */
#define SHT_MIPS_DEBUG         0x70000005 /* MIPS ECOFF debugging information*/
#define SHT_MIPS_REGINFO       0x70000006 /* Register usage information */
#define SHT_MIPS_PACKAGE       0x70000007
#define SHT_MIPS_PACKSYM       0x70000008
#define SHT_MIPS_RELD          0x70000009
#define SHT_MIPS_IFACE         0x7000000b
#define SHT_MIPS_CONTENT       0x7000000c
#define SHT_MIPS_OPTIONS       0x7000000d /* Miscellaneous options.  */
#define SHT_MIPS_SHDR          0x70000010
#define SHT_MIPS_FDESC         0x70000011
#define SHT_MIPS_EXTSYM        0x70000012
#define SHT_MIPS_DENSE         0x70000013
#define SHT_MIPS_PDESC         0x70000014
#define SHT_MIPS_LOCSYM        0x70000015
#define SHT_MIPS_AUXSYM        0x70000016
#define SHT_MIPS_OPTSYM        0x70000017
#define SHT_MIPS_LOCSTR        0x70000018
#define SHT_MIPS_LINE          0x70000019
#define SHT_MIPS_RFDESC        0x7000001a
#define SHT_MIPS_DELTASYM      0x7000001b
#define SHT_MIPS_DELTAINST     0x7000001c
#define SHT_MIPS_DELTACLASS    0x7000001d
#define SHT_MIPS_DWARF         0x7000001e /* DWARF debugging information.  */
#define SHT_MIPS_DELTADECL     0x7000001f
#define SHT_MIPS_SYMBOL_LIB    0x70000020
#define SHT_MIPS_EVENTS        0x70000021 /* Event section.  */
#define SHT_MIPS_TRANSLATE     0x70000022
#define SHT_MIPS_PIXIE         0x70000023
#define SHT_MIPS_XLATE         0x70000024
#define SHT_MIPS_XLATE_DEBUG   0x70000025
#define SHT_MIPS_WHIRL         0x70000026
#define SHT_MIPS_EH_REGION     0x70000027
#define SHT_MIPS_XLATE_OLD     0x70000028
#define SHT_MIPS_PDR_EXCEPTION 0x70000029

/* Legal values for sh_flags field of Elf32_Shdr.  */

#define SHF_MIPS_GPREL   0x10000000     /* Must be part of global data area */
#define SHF_MIPS_MERGE   0x20000000
#define SHF_MIPS_ADDR    0x40000000
#define SHF_MIPS_STRINGS 0x80000000
#define SHF_MIPS_NOSTRIP 0x08000000
#define SHF_MIPS_LOCAL   0x04000000
#define SHF_MIPS_NAMES   0x02000000
#define SHF_MIPS_NODUPE  0x01000000


/* Symbol tables.  */

/* MIPS specific values for `st_other'.  */
#define STO_MIPS_DEFAULT                0x0
#define STO_MIPS_INTERNAL               0x1
#define STO_MIPS_HIDDEN                 0x2
#define STO_MIPS_PROTECTED              0x3
#define STO_MIPS_SC_ALIGN_UNUSED        0xff

/* MIPS specific values for `st_info'.  */
#define STB_MIPS_SPLIT_COMMON           13

/* Entries found in sections of type SHT_MIPS_GPTAB.  */

typedef union
{
  struct
    {
      Elf32_Word gt_current_g_value;    /* -G value used for compilation */
      Elf32_Word gt_unused;             /* Not used */
    } gt_header;                        /* First entry in section */
  struct
    {
      Elf32_Word gt_g_value;            /* If this value were used for -G */
      Elf32_Word gt_bytes;              /* This many bytes would be used */
    } gt_entry;                         /* Subsequent entries in section */
} Elf32_gptab;

/* Entry found in sections of type SHT_MIPS_REGINFO.  */

typedef struct
{
  Elf32_Word    ri_gprmask;             /* General registers used */
  Elf32_Word    ri_cprmask[4];          /* Coprocessor registers used */
  Elf32_Sword   ri_gp_value;            /* $gp register value */
} Elf32_RegInfo;

/* Entries found in sections of type SHT_MIPS_OPTIONS.  */

typedef struct
{
  unsigned char kind;           /* Determines interpretation of the
                                   variable part of descriptor.  */
  unsigned char size;           /* Size of descriptor, including header.  */
  Elf32_Section section;        /* Section header index of section affected,
                                   0 for global options.  */
  Elf32_Word info;              /* Kind-specific information.  */
} Elf_Options;

/* Values for `kind' field in Elf_Options.  */

#define ODK_NULL        0       /* Undefined.  */
#define ODK_REGINFO     1       /* Register usage information.  */
#define ODK_EXCEPTIONS  2       /* Exception processing options.  */
#define ODK_PAD         3       /* Section padding options.  */
#define ODK_HWPATCH     4       /* Hardware workarounds performed */
#define ODK_FILL        5       /* record the fill value used by the linker. */
#define ODK_TAGS        6       /* reserve space for desktop tools to write. */
#define ODK_HWAND       7       /* HW workarounds.  'AND' bits when merging. */
#define ODK_HWOR        8       /* HW workarounds.  'OR' bits when merging.  */

/* Values for `info' in Elf_Options for ODK_EXCEPTIONS entries.  */

#define OEX_FPU_MIN     0x1f    /* FPE's which MUST be enabled.  */
#define OEX_FPU_MAX     0x1f00  /* FPE's which MAY be enabled.  */
#define OEX_PAGE0       0x10000 /* page zero must be mapped.  */
#define OEX_SMM         0x20000 /* Force sequential memory mode?  */
#define OEX_FPDBUG      0x40000 /* Force floating point debug mode?  */
#define OEX_PRECISEFP   OEX_FPDBUG
#define OEX_DISMISS     0x80000 /* Dismiss invalid address faults?  */

#define OEX_FPU_INVAL   0x10
#define OEX_FPU_DIV0    0x08
#define OEX_FPU_OFLO    0x04
#define OEX_FPU_UFLO    0x02
#define OEX_FPU_INEX    0x01

/* Masks for `info' in Elf_Options for an ODK_HWPATCH entry.  */

#define OHW_R4KEOP      0x1     /* R4000 end-of-page patch.  */
#define OHW_R8KPFETCH   0x2     /* may need R8000 prefetch patch.  */
#define OHW_R5KEOP      0x4     /* R5000 end-of-page patch.  */
#define OHW_R5KCVTL     0x8     /* R5000 cvt.[ds].l bug.  clean=1.  */

#define OPAD_PREFIX     0x1
#define OPAD_POSTFIX    0x2
#define OPAD_SYMBOL     0x4

/* Entry found in `.options' section.  */

typedef struct
{
  Elf32_Word hwp_flags1;        /* Extra flags.  */
  Elf32_Word hwp_flags2;        /* Extra flags.  */
} Elf_Options_Hw;

/* Masks for `info' in ElfOptions for ODK_HWAND and ODK_HWOR entries.  */

#define OHWA0_R4KEOP_CHECKED    0x00000001
#define OHWA1_R4KEOP_CLEAN      0x00000002

/* MIPS relocs.  */

#define R_MIPS_NONE             0       /* No reloc */
#define R_MIPS_16               1       /* Direct 16 bit */
#define R_MIPS_32               2       /* Direct 32 bit */
#define R_MIPS_REL32            3       /* PC relative 32 bit */
#define R_MIPS_26               4       /* Direct 26 bit shifted */
#define R_MIPS_HI16             5       /* High 16 bit */
#define R_MIPS_LO16             6       /* Low 16 bit */
#define R_MIPS_GPREL16          7       /* GP relative 16 bit */
#define R_MIPS_LITERAL          8       /* 16 bit literal entry */
#define R_MIPS_GOT16            9       /* 16 bit GOT entry */
#define R_MIPS_PC16             10      /* PC relative 16 bit */
#define R_MIPS_CALL16           11      /* 16 bit GOT entry for function */
#define R_MIPS_GPREL32          12      /* GP relative 32 bit */

#define R_MIPS_SHIFT5           16
#define R_MIPS_SHIFT6           17
#define R_MIPS_64               18
#define R_MIPS_GOT_DISP         19
#define R_MIPS_GOT_PAGE         20
#define R_MIPS_GOT_OFST         21
#define R_MIPS_GOT_HI16         22
#define R_MIPS_GOT_LO16         23
#define R_MIPS_SUB              24
#define R_MIPS_INSERT_A         25
#define R_MIPS_INSERT_B         26
#define R_MIPS_DELETE           27
#define R_MIPS_HIGHER           28
#define R_MIPS_HIGHEST          29
#define R_MIPS_CALL_HI16        30
#define R_MIPS_CALL_LO16        31
#define R_MIPS_SCN_DISP         32
#define R_MIPS_REL16            33
#define R_MIPS_ADD_IMMEDIATE    34
#define R_MIPS_PJUMP            35
#define R_MIPS_RELGOT           36
#define R_MIPS_JALR             37
/* Keep this the last entry.  */
#define R_MIPS_NUM              38

/* Legal values for p_type field of Elf32_Phdr.  */

#define PT_MIPS_REGINFO 0x70000000      /* Register usage information */
#define PT_MIPS_RTPROC  0x70000001      /* Runtime procedure table. */
#define PT_MIPS_OPTIONS 0x70000002

/* Special program header types.  */

#define PF_MIPS_LOCAL   0x10000000

/* Legal values for d_tag field of Elf32_Dyn.  */

#define DT_MIPS_RLD_VERSION  0x70000001 /* Runtime linker interface version */
#define DT_MIPS_TIME_STAMP   0x70000002 /* Timestamp */
#define DT_MIPS_ICHECKSUM    0x70000003 /* Checksum */
#define DT_MIPS_IVERSION     0x70000004 /* Version string (string tbl index) */
#define DT_MIPS_FLAGS        0x70000005 /* Flags */
#define DT_MIPS_BASE_ADDRESS 0x70000006 /* Base address */
#define DT_MIPS_MSYM         0x70000007
#define DT_MIPS_CONFLICT     0x70000008 /* Address of CONFLICT section */
#define DT_MIPS_LIBLIST      0x70000009 /* Address of LIBLIST section */
#define DT_MIPS_LOCAL_GOTNO  0x7000000a /* Number of local GOT entries */
#define DT_MIPS_CONFLICTNO   0x7000000b /* Number of CONFLICT entries */
#define DT_MIPS_LIBLISTNO    0x70000010 /* Number of LIBLIST entries */
#define DT_MIPS_SYMTABNO     0x70000011 /* Number of DYNSYM entries */
#define DT_MIPS_UNREFEXTNO   0x70000012 /* First external DYNSYM */
#define DT_MIPS_GOTSYM       0x70000013 /* First GOT entry in DYNSYM */
#define DT_MIPS_HIPAGENO     0x70000014 /* Number of GOT page table entries */
#define DT_MIPS_RLD_MAP      0x70000016 /* Address of run time loader map.  */
#define DT_MIPS_DELTA_CLASS  0x70000017 /* Delta C++ class definition.  */
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
#define DT_MIPS_OPTIONS      0x70000029 /* Address of .options.  */
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
#define DT_MIPS_NUM          0x32

/* Legal values for DT_MIPS_FLAGS Elf32_Dyn entry.  */

#define RHF_NONE                   0            /* No flags */
#define RHF_QUICKSTART             (1 << 0)     /* Use quickstart */
#define RHF_NOTPOT                 (1 << 1)     /* Hash size not power of 2 */
#define RHF_NO_LIBRARY_REPLACEMENT (1 << 2)     /* Ignore LD_LIBRARY_PATH */
#define RHF_NO_MOVE                (1 << 3)
#define RHF_SGI_ONLY               (1 << 4)
#define RHF_GUARANTEE_INIT         (1 << 5)
#define RHF_DELTA_C_PLUS_PLUS      (1 << 6)
#define RHF_GUARANTEE_START_INIT   (1 << 7)
#define RHF_PIXIE                  (1 << 8)
#define RHF_DEFAULT_DELAY_LOAD     (1 << 9)
#define RHF_REQUICKSTART           (1 << 10)
#define RHF_REQUICKSTARTED         (1 << 11)
#define RHF_CORD                   (1 << 12)
#define RHF_NO_UNRES_UNDEF         (1 << 13)
#define RHF_RLD_ORDER_SAFE         (1 << 14)

/* Entries found in sections of type SHT_MIPS_LIBLIST.  */

typedef struct
{
  Elf32_Word l_name;            /* Name (string table index) */
  Elf32_Word l_time_stamp;      /* Timestamp */
  Elf32_Word l_checksum;        /* Checksum */
  Elf32_Word l_version;         /* Interface version */
  Elf32_Word l_flags;           /* Flags */
} Elf32_Lib;

typedef struct
{
  Elf64_Word l_name;            /* Name (string table index) */
  Elf64_Word l_time_stamp;      /* Timestamp */
  Elf64_Word l_checksum;        /* Checksum */
  Elf64_Word l_version;         /* Interface version */
  Elf64_Word l_flags;           /* Flags */
} Elf64_Lib;


/* Legal values for l_flags.  */

#define LL_NONE           0
#define LL_EXACT_MATCH    (1 << 0)      /* Require exact match */
#define LL_IGNORE_INT_VER (1 << 1)      /* Ignore interface version */
#define LL_REQUIRE_MINOR  (1 << 2)
#define LL_EXPORTS        (1 << 3)
#define LL_DELAY_LOAD     (1 << 4)
#define LL_DELTA          (1 << 5)

/* Entries found in sections of type SHT_MIPS_CONFLICT.  */

typedef Elf32_Addr Elf32_Conflict;


/* HPPA specific definitions.  */

/* Legal values for e_flags field of Elf32_Ehdr.  */

#define EF_PARISC_TRAPNL        1       /* Trap nil pointer dereference.  */
#define EF_PARISC_EXT           2       /* Program uses arch. extensions.  */
#define EF_PARISC_ARCH          0xffff0000 /* Architecture version.  */
/* Defined values are:
                                0x020b  PA-RISC 1.0 big-endian
                                0x0210  PA-RISC 1.1 big-endian
                                0x028b  PA-RISC 1.0 little-endian
                                0x0290  PA-RISC 1.1 little-endian
*/

/* Legal values for sh_type field of Elf32_Shdr.  */

#define SHT_PARISC_GOT          0x70000000 /* GOT for external data.  */
#define SHT_PARISC_ARCH         0x70000001 /* Architecture extensions.  */
#define SHT_PARISC_GLOBAL       0x70000002 /* Definition of $global$.  */
#define SHT_PARISC_MILLI        0x70000003 /* Millicode routines.  */
#define SHT_PARISC_UNWIND       0x70000004 /* Unwind information.  */
#define SHT_PARISC_PLT          0x70000005 /* Procedure linkage table.  */
#define SHT_PARISC_SDATA        0x70000006 /* Short initialized data.  */
#define SHT_PARISC_SBSS         0x70000007 /* Short uninitialized data.  */
#define SHT_PARISC_SYMEXTN      0x70000008 /* Argument/relocation info.  */
#define SHT_PARISC_STUBS        0x70000009 /* Linker stubs.  */

/* Legal values for sh_flags field of Elf32_Shdr.  */

#define SHF_PARISC_GLOBAL       0x10000000 /* Section defines dp.  */
#define SHF_PARISC_SHORT        0x20000000 /* Section with short addressing. */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_PARISC_MILLICODE    13      /* Millicode function entry point.  */

/* HPPA relocs.  */

#define R_PARISC_NONE           0       /* No reloc.  */
#define R_PARISC_DIR32          1       /* Direct 32-bit reference.  */
#define R_PARISC_DIR21L         2       /* Left 21 bits of eff. address.  */
#define R_PARISC_DIR17R         3       /* Right 17 bits of eff. address.  */
#define R_PARISC_DIR14R         4       /* Right 14 bits of eff. address.  */
#define R_PARISC_PCREL21L       5       /* PC-relative, left 21 bits.  */
#define R_PARISC_PCREL14R       6       /* PC-relative, right 14 bits.  */
#define R_PARISC_PCREL17C       7       /* Conditional PC-relative, ignore
                                           if displacement > 17bits.  */
#define R_PARISC_PCREL17F       8       /* Conditional PC-relative, must
                                           fit in 17bits.  */
#define R_PARISC_DPREL21L       9       /* DP-relative, left 21 bits.  */
#define R_PARISC_DPREL14R       10      /* DP-relative, right 14 bits.  */
#define R_PARISC_DPREL14F       11      /* DP-relative, must bit in 14 bits. */
#define R_PARISC_DLTREL21L      12      /* DLT-relative, left 21 bits.  */
#define R_PARISC_DLTREL14R      13      /* DLT-relative, right 14 bits.  */
#define R_PARISC_DLTREL14F      14      /* DLT-relative, must fit in 14 bits.*/
#define R_PARISC_DLTIND21L      15      /* DLT-relative indirect, left
                                           21 bits.  */
#define R_PARISC_DLTIND14R      16      /* DLT-relative indirect, right
                                           14 bits.  */
#define R_PARISC_DLTIND14F      17      /* DLT-relative indirect, must fit
                                           int 14 bits.  */
#define R_PARISC_PLABEL32       18      /* Direct 32-bit reference to proc.  */

/* Alpha specific definitions.  */

/* Legal values for e_flags field of Elf64_Ehdr.  */

#define EF_ALPHA_32BIT          1       /* All addresses must be < 2GB.  */
#define EF_ALPHA_CANRELAX       2       /* Relocations for relaxing exist.  */

/* Legal values for sh_type field of Elf64_Shdr.  */

/* These two are primerily concerned with ECOFF debugging info.  */
#define SHT_ALPHA_DEBUG         0x70000001
#define SHT_ALPHA_REGINFO       0x70000002

/* Legal values for sh_flags field of Elf64_Shdr.  */

#define SHF_ALPHA_GPREL         0x10000000

/* Legal values for st_other field of Elf64_Sym.  */
#define STO_ALPHA_NOPV          0x80    /* No PV required.  */
#define STO_ALPHA_STD_GPLOAD    0x88    /* PV only used for initial ldgp.  */

/* Alpha relocs.  */

#define R_ALPHA_NONE            0       /* No reloc */
#define R_ALPHA_REFLONG         1       /* Direct 32 bit */
#define R_ALPHA_REFQUAD         2       /* Direct 64 bit */
#define R_ALPHA_GPREL32         3       /* GP relative 32 bit */
#define R_ALPHA_LITERAL         4       /* GP relative 16 bit w/optimization */
#define R_ALPHA_LITUSE          5       /* Optimization hint for LITERAL */
#define R_ALPHA_GPDISP          6       /* Add displacement to GP */
#define R_ALPHA_BRADDR          7       /* PC+4 relative 23 bit shifted */
#define R_ALPHA_HINT            8       /* PC+4 relative 16 bit shifted */
#define R_ALPHA_SREL16          9       /* PC relative 16 bit */
#define R_ALPHA_SREL32          10      /* PC relative 32 bit */
#define R_ALPHA_SREL64          11      /* PC relative 64 bit */
#define R_ALPHA_OP_PUSH         12      /* OP stack push */
#define R_ALPHA_OP_STORE        13      /* OP stack pop and store */
#define R_ALPHA_OP_PSUB         14      /* OP stack subtract */
#define R_ALPHA_OP_PRSHIFT      15      /* OP stack right shift */
#define R_ALPHA_GPVALUE         16
#define R_ALPHA_GPRELHIGH       17
#define R_ALPHA_GPRELLOW        18
#define R_ALPHA_IMMED_GP_16     19
#define R_ALPHA_IMMED_GP_HI32   20
#define R_ALPHA_IMMED_SCN_HI32  21
#define R_ALPHA_IMMED_BR_HI32   22
#define R_ALPHA_IMMED_LO32      23
#define R_ALPHA_COPY            24      /* Copy symbol at runtime */
#define R_ALPHA_GLOB_DAT        25      /* Create GOT entry */
#define R_ALPHA_JMP_SLOT        26      /* Create PLT entry */
#define R_ALPHA_RELATIVE        27      /* Adjust by program base */
/* Keep this the last entry.  */
#define R_ALPHA_NUM             28


/* PowerPC specific declarations */

/* PowerPC relocations defined by the ABIs */
#define R_PPC_NONE              0
#define R_PPC_ADDR32            1       /* 32bit absolute address */
#define R_PPC_ADDR24            2       /* 26bit address, 2 bits ignored.  */
#define R_PPC_ADDR16            3       /* 16bit absolute address */
#define R_PPC_ADDR16_LO         4       /* lower 16bit of absolute address */
#define R_PPC_ADDR16_HI         5       /* high 16bit of absolute address */
#define R_PPC_ADDR16_HA         6       /* adjusted high 16bit */
#define R_PPC_ADDR14            7       /* 16bit address, 2 bits ignored */
#define R_PPC_ADDR14_BRTAKEN    8
#define R_PPC_ADDR14_BRNTAKEN   9
#define R_PPC_REL24             10      /* PC relative 26 bit */
#define R_PPC_REL14             11      /* PC relative 16 bit */
#define R_PPC_REL14_BRTAKEN     12
#define R_PPC_REL14_BRNTAKEN    13
#define R_PPC_GOT16             14
#define R_PPC_GOT16_LO          15
#define R_PPC_GOT16_HI          16
#define R_PPC_GOT16_HA          17
#define R_PPC_PLTREL24          18
#define R_PPC_COPY              19
#define R_PPC_GLOB_DAT          20
#define R_PPC_JMP_SLOT          21
#define R_PPC_RELATIVE          22
#define R_PPC_LOCAL24PC         23
#define R_PPC_UADDR32           24
#define R_PPC_UADDR16           25
#define R_PPC_REL32             26
#define R_PPC_PLT32             27
#define R_PPC_PLTREL32          28
#define R_PPC_PLT16_LO          29
#define R_PPC_PLT16_HI          30
#define R_PPC_PLT16_HA          31
#define R_PPC_SDAREL16          32
#define R_PPC_SECTOFF           33
#define R_PPC_SECTOFF_LO        34
#define R_PPC_SECTOFF_HI        35
#define R_PPC_SECTOFF_HA        36
/* Keep this the last entry.  */
#define R_PPC_NUM               37

/* The remaining relocs are from the Embedded ELF ABI, and are not
   in the SVR4 ELF ABI.  */
#define R_PPC_EMB_NADDR32       101
#define R_PPC_EMB_NADDR16       102
#define R_PPC_EMB_NADDR16_LO    103
#define R_PPC_EMB_NADDR16_HI    104
#define R_PPC_EMB_NADDR16_HA    105
#define R_PPC_EMB_SDAI16        106
#define R_PPC_EMB_SDA2I16       107
#define R_PPC_EMB_SDA2REL       108
#define R_PPC_EMB_SDA21         109     /* 16 bit offset in SDA */
#define R_PPC_EMB_MRKREF        110
#define R_PPC_EMB_RELSEC16      111
#define R_PPC_EMB_RELST_LO      112
#define R_PPC_EMB_RELST_HI      113
#define R_PPC_EMB_RELST_HA      114
#define R_PPC_EMB_BIT_FLD       115
#define R_PPC_EMB_RELSDA        116     /* 16 bit relative offset in SDA */

/* Diab tool relocations.  */
#define R_PPC_DIAB_SDA21_LO     180     /* like EMB_SDA21, but lower 16 bit */
#define R_PPC_DIAB_SDA21_HI     181     /* like EMB_SDA21, but high 16 bit */
#define R_PPC_DIAB_SDA21_HA     182     /* like EMB_SDA21, adjusted high 16 */
#define R_PPC_DIAB_RELSDA_LO    183     /* like EMB_RELSDA, but lower 16 bit */
#define R_PPC_DIAB_RELSDA_HI    184     /* like EMB_RELSDA, but high 16 bit */
#define R_PPC_DIAB_RELSDA_HA    185     /* like EMB_RELSDA, adjusted high 16 */

/* This is a phony reloc to handle any old fashioned TOC16 references
   that may still be in object files.  */
#define R_PPC_TOC16             255


/* ARM specific declarations */

/* Processor specific flags for the ELF header e_flags field.  */
#define EF_ARM_RELEXEC     0x01
#define EF_ARM_HASENTRY    0x02
#define EF_ARM_INTERWORK   0x04
#define EF_ARM_APCS_26     0x08
#define EF_ARM_APCS_FLOAT  0x10
#define EF_ARM_PIC         0x20
#define EF_ALIGN8          0x40         /* 8-bit structure alignment is in use */
#define EF_NEW_ABI         0x80
#define EF_OLD_ABI         0x100

/* Additional symbol types for Thumb */
#define STT_ARM_TFUNC      0xd

/* ARM-specific values for sh_flags */
#define SHF_ARM_ENTRYSECT  0x10000000   /* Section contains an entry point */
#define SHF_ARM_COMDEF     0x80000000   /* Section may be multiply defined
                                           in the input to a link step */

/* ARM-specific program header flags */
#define PF_ARM_SB          0x10000000   /* Segment contains the location
                                           addressed by the static base */

/* ARM relocs.  */
#define R_ARM_NONE              0       /* No reloc */
#define R_ARM_PC24              1       /* PC relative 26 bit branch */
#define R_ARM_ABS32             2       /* Direct 32 bit  */
#define R_ARM_REL32             3       /* PC relative 32 bit */
#define R_ARM_PC13              4
#define R_ARM_ABS16             5       /* Direct 16 bit */
#define R_ARM_ABS12             6       /* Direct 12 bit */
#define R_ARM_THM_ABS5          7
#define R_ARM_ABS8              8       /* Direct 8 bit */
#define R_ARM_SBREL32           9
#define R_ARM_THM_CALL          10
#define R_ARM_THM_PC8           11
#define R_ARM_AMP_VCALL9        12
#define R_ARM_SWI24             13
#define R_ARM_THM_SWI8          14
#define R_ARM_XPC25             15
#define R_ARM_THM_XPC22         16
#define R_ARM_COPY              20      /* Copy symbol at runtime */
#define R_ARM_GLOB_DAT          21      /* Create GOT entry */
#define R_ARM_JUMP_SLOT         22      /* Create PLT entry */
#define R_ARM_RELATIVE          23      /* Adjust by program base */
#define R_ARM_GOTOFF32          24      /* 32 bit offset to GOT */
#define R_ARM_BASE_PREL         25      /* 32 bit PC relative offset to GOT */
#define R_ARM_GOT_BREL          26      /* 32 bit GOT entry */
#define R_ARM_PLT32             27      /* 32 bit PLT address */
#define R_ARM_CALL              28
#define R_ARM_JUMP24            29
#define R_ARM_THM_JUMP24        30
#define R_ARM_V4BX              40
#define R_ARM_PREL31            42
#define R_ARM_MOVW_ABS_NC       43
#define R_ARM_MOVT_ABS          44
#define R_ARM_THM_MOVW_ABS_NC   47
#define R_ARM_THM_MOVT_ABS      48
#define R_ARM_GNU_VTENTRY       100
#define R_ARM_GNU_VTINHERIT     101
#define R_ARM_THM_PC11          102     /* thumb unconditional branch */
#define R_ARM_THM_PC9           103     /* thumb conditional branch */
#define R_ARM_RXPC25            249
#define R_ARM_RSBREL32          250
#define R_ARM_THM_RPC22         251
#define R_ARM_RREL32            252
#define R_ARM_RABS22            253
#define R_ARM_RPC24             254
#define R_ARM_RBASE             255
/* Keep this the last entry.  */
#define R_ARM_NUM               256

/* TMS320C67xx specific declarations */
/* XXX: no ELF standard yet */

/* TMS320C67xx relocs. */
#define R_C60_32       1
#define R_C60_GOT32     3               /* 32 bit GOT entry */
#define R_C60_PLT32     4               /* 32 bit PLT address */
#define R_C60_COPY      5               /* Copy symbol at runtime */
#define R_C60_GLOB_DAT  6               /* Create GOT entry */
#define R_C60_JMP_SLOT  7               /* Create PLT entry */
#define R_C60_RELATIVE  8               /* Adjust by program base */
#define R_C60_GOTOFF    9               /* 32 bit offset to GOT */
#define R_C60_GOTPC     10              /* 32 bit PC relative offset to GOT */

#define R_C60HI16      0x55       /* high 16 bit MVKH embedded */
#define R_C60LO16      0x54       /* low 16 bit MVKL embedded */

#endif  /* elf.h */
