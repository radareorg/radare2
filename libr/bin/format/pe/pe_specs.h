/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#undef PE_
#undef ILT_MASK1
#undef ILT_MASK2
#undef PE_Word
#undef PE_DWord
#undef PE_CWord

#ifdef R_BIN_PE64
#define PE_(name) Pe64_##name 
#define ILT_MASK1 0x8000000000000000LL
#define ILT_MASK2 0x7fffffffffffffffLL
#define PE_Word u16
#define PE_DWord u64
#define PE_CWord u32
#else
#define PE_(name) Pe32_##name 
#define ILT_MASK1 0x80000000
#define ILT_MASK2 0x7fffffff
#define PE_Word u16
#define PE_DWord u32
#define PE_CWord u32
#endif

#ifndef _INCLUDE_R_BIN_PE_SPECS_H_
#define _INCLUDE_R_BIN_PE_SPECS_H_

#define PE_NAME_LENGTH 256
#define PE_STRING_LENGTH 256

typedef struct {
	u16 e_magic;      /* 00: MZ Header signature */
	u16 e_cblp;       /* 02: Bytes on last page of file */
	u16 e_cp;         /* 04: Pages in file */
	u16 e_crlc;       /* 06: Relocations */
	u16 e_cparhdr;    /* 08: Size of header in paragraphs */
	u16 e_minalloc;   /* 0a: Minimum extra paragraphs needed */
	u16 e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
	u16 e_ss;         /* 0e: Initial (relative) SS value */
	u16 e_sp;         /* 10: Initial SP value */
	u16 e_csum;       /* 12: Checksum */
	u16 e_ip;         /* 14: Initial IP value */
	u16 e_cs;         /* 16: Initial (relative) CS value */
	u16 e_lfarlc;     /* 18: File address of relocation table */
	u16 e_ovno;       /* 1a: Overlay number */
	u16 e_res[4];     /* 1c: Reserved words */
	u16 e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
	u16 e_oeminfo;    /* 26: OEM information; e_oemid specific */
	u16 e_res2[10];   /* 28: Reserved words */
	u32 e_lfanew;     /* 3c: Offset to extended header */
} Pe32_image_dos_header, Pe64_image_dos_header;

#define PE_IMAGE_FILE_TYPE_PE32                0x10b
#define PE_IMAGE_FILE_TYPE_PE32PLUS            0x20b

#define PE_IMAGE_FILE_MACHINE_UNKNOWN          0x0000
#define PE_IMAGE_FILE_MACHINE_ALPHA            0x0184
#define PE_IMAGE_FILE_MACHINE_ALPHA64          0x0284
#define PE_IMAGE_FILE_MACHINE_AM33             0x01d3
#define PE_IMAGE_FILE_MACHINE_AMD64            0x8664
#define PE_IMAGE_FILE_MACHINE_ARM              0x01c0
#define PE_IMAGE_FILE_MACHINE_AXP64            PE_IMAGE_FILE_MACHINE_ALPHA64
#define PE_IMAGE_FILE_MACHINE_CEE              0xc0ee
#define PE_IMAGE_FILE_MACHINE_CEF              0x0cef
#define PE_IMAGE_FILE_MACHINE_EBC              0x0ebc
#define PE_IMAGE_FILE_MACHINE_I386             0x014c
#define PE_IMAGE_FILE_MACHINE_IA64             0x0200
#define PE_IMAGE_FILE_MACHINE_M32R             0x9041
#define PE_IMAGE_FILE_MACHINE_M68K             0x0268
#define PE_IMAGE_FILE_MACHINE_MIPS16           0x0266
#define PE_IMAGE_FILE_MACHINE_MIPSFPU          0x0366
#define PE_IMAGE_FILE_MACHINE_MIPSFPU16        0x0466
#define PE_IMAGE_FILE_MACHINE_POWERPC          0x01f0
#define PE_IMAGE_FILE_MACHINE_POWERPCFP        0x01f1
#define PE_IMAGE_FILE_MACHINE_R10000           0x0168
#define PE_IMAGE_FILE_MACHINE_R3000            0x0162
#define PE_IMAGE_FILE_MACHINE_R4000            0x0166
#define PE_IMAGE_FILE_MACHINE_SH3              0x01a2
#define PE_IMAGE_FILE_MACHINE_SH3DSP           0x01a3
#define PE_IMAGE_FILE_MACHINE_SH3E             0x01a4
#define PE_IMAGE_FILE_MACHINE_SH4              0x01a6
#define PE_IMAGE_FILE_MACHINE_SH5              0x01a8
#define PE_IMAGE_FILE_MACHINE_THUMB            0x01c2
#define PE_IMAGE_FILE_MACHINE_TRICORE          0x0520
#define PE_IMAGE_FILE_MACHINE_WCEMIPSV2        0x0169

#define PE_IMAGE_FILE_RELOCS_STRIPPED          0x0001
#define PE_IMAGE_FILE_EXECUTABLE_IMAGE         0x0002
#define PE_IMAGE_FILE_LINE_NUMS_STRIPPED       0x0004
#define PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED      0x0008
#define PE_IMAGE_FILE_AGGRESSIVE_WS_TRIM       0x0010
#define PE_IMAGE_FILE_LARGE_ADDRESS_AWARE      0x0020
#define PE_IMAGE_FILE_16BIT_MACHINE            0x0040
#define PE_IMAGE_FILE_BYTES_REVERSED_LO        0x0080
#define PE_IMAGE_FILE_32BIT_MACHINE            0x0100
#define PE_IMAGE_FILE_DEBUG_STRIPPED           0x0200
#define PE_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  0x0400
#define PE_IMAGE_FILE_NET_RUN_FROM_SWAP        0x0800
#define PE_IMAGE_FILE_SYSTEM                   0x1000
#define PE_IMAGE_FILE_DLL                      0x2000
#define PE_IMAGE_FILE_UP_SYSTEM_ONLY           0x4000
#define PE_IMAGE_FILE_BYTES_REVERSED_HI        0x8000

typedef struct {
	u16 Machine;
	u16 NumberOfSections;
	u32 TimeDateStamp;
	u32 PointerToSymbolTable;
	u32 NumberOfSymbols;
	u16 SizeOfOptionalHeader;
	u16 Characteristics;
} Pe32_image_file_header, Pe64_image_file_header;

#define PE_IMAGE_DIRECTORY_ENTRIES                 16
#define PE_IMAGE_DIRECTORY_ENTRY_EXPORT             0
#define PE_IMAGE_DIRECTORY_ENTRY_IMPORT             1
#define PE_IMAGE_DIRECTORY_ENTRY_RESOURCE           2
#define PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION          3
#define PE_IMAGE_DIRECTORY_ENTRY_SECURITY           4
#define PE_IMAGE_DIRECTORY_ENTRY_BASERELOC          5
#define PE_IMAGE_DIRECTORY_ENTRY_DEBUG              6
#define PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT          7
#define PE_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE       7
#define PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR          8
#define PE_IMAGE_DIRECTORY_ENTRY_TLS                9
#define PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10
#define PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11
#define PE_IMAGE_DIRECTORY_ENTRY_IAT               12
#define PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13
#define PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14

#define PE_IMAGE_SUBSYSTEM_UNKNOWN                  0
#define PE_IMAGE_SUBSYSTEM_NATIVE                   1
#define PE_IMAGE_SUBSYSTEM_WINDOWS_GUI              2
#define PE_IMAGE_SUBSYSTEM_WINDOWS_CUI              3
#define PE_IMAGE_SUBSYSTEM_POSIX_CUI                7
#define PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           9
#define PE_IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define PE_IMAGE_SUBSYSTEM_EFI_ROM                 13
#define PE_IMAGE_SUBSYSTEM_XBOX                    14

typedef struct {
	u32 VirtualAddress;
	u32 Size;
} Pe32_image_data_directory, Pe64_image_data_directory;

typedef struct {
	/* Standard fields */
	u16 Magic;
	u8  MajorLinkerVersion;
	u8  MinorLinkerVersion;
	u32 SizeOfCode;
	u32 SizeOfInitializedData;
	u32 SizeOfUninitializedData;
	u32 AddressOfEntryPoint;
	u32 BaseOfCode;
	u32 BaseOfData;
	/* NT additional fields */
	u32 ImageBase;
	u32 SectionAlignment;
	u32 FileAlignment;
	u16 MajorOperatingSystemVersion;
	u16 MinorOperatingSystemVersion;
	u16 MajorImageVersion;
	u16 MinorImageVersion;
	u16 MajorSubsystemVersion;
	u16 MinorSubsystemVersion;
	u32 Win32VersionValue;
	u32 SizeOfImage;
	u32 SizeOfHeaders;
	u32 CheckSum;
	u16 Subsystem;
	u16 DllCharacteristics;
	u32 SizeOfStackReserve;
	u32 SizeOfStackCommit;
	u32 SizeOfHeapReserve;
	u32 SizeOfHeapCommit;
	u32 LoaderFlags;
	u32 NumberOfRvaAndSizes;
	Pe32_image_data_directory DataDirectory[PE_IMAGE_DIRECTORY_ENTRIES];
} Pe32_image_optional_header;

typedef struct {
	/* Standard fields */
	u16 Magic;
	u8  MajorLinkerVersion;
	u8  MinorLinkerVersion;
	u32 SizeOfCode;
	u32 SizeOfInitializedData;
	u32 SizeOfUninitializedData;
	u32 AddressOfEntryPoint;
	u32 BaseOfCode;
	/* NT additional fields */
	u64 ImageBase;
	u32 SectionAlignment;
	u32 FileAlignment;
	u16 MajorOperatingSystemVersion;
	u16 MinorOperatingSystemVersion;
	u16 MajorImageVersion;
	u16 MinorImageVersion;
	u16 MajorSubsystemVersion;
	u16 MinorSubsystemVersion;
	u32 Win32VersionValue;
	u32 SizeOfImage;
	u32 SizeOfHeaders;
	u32 CheckSum;
	u16 Subsystem;
	u16 DllCharacteristics;
	u64 SizeOfStackReserve;
	u64 SizeOfStackCommit;
	u64 SizeOfHeapReserve;
	u64 SizeOfHeapCommit;
	u32 LoaderFlags;
	u32 NumberOfRvaAndSizes;
	Pe64_image_data_directory DataDirectory[PE_IMAGE_DIRECTORY_ENTRIES];
} Pe64_image_optional_header;

#define PE_IMAGE_SIZEOF_SHORT_NAME 8

#define PE_IMAGE_SCN_MEM_SHARED    0x10000000
#define PE_IMAGE_SCN_MEM_EXECUTE   0x20000000
#define PE_IMAGE_SCN_MEM_READ      0x40000000
#define PE_IMAGE_SCN_MEM_WRITE     0x80000000

typedef struct {
	u8  Name[PE_IMAGE_SIZEOF_SHORT_NAME];
	union {
		u32 PhysicalAddress;
		u32 VirtualSize;
	} Misc;
	u32 VirtualAddress;
	u32 SizeOfRawData;
	u32 PointerToRawData;
	u32 PointerToRelocations;
	u32 PointerToLinenumbers;
	u16 NumberOfRelocations;
	u16 NumberOfLinenumbers;
	u32 Characteristics;
} Pe32_image_section_header, Pe64_image_section_header;

typedef struct {
	u32 Characteristics;
	u32 TimeDateStamp;
	u16 MajorVersion;
	u16 MinorVersion;
	u32 Name;
	u32 Base;
	u32 NumberOfFunctions;
	u32 NumberOfNames;
	u32 AddressOfFunctions;
	u32 AddressOfNames;
	u32 AddressOfOrdinals;
} Pe32_image_export_directory, Pe64_image_export_directory;

typedef struct {
	u32 Characteristics;
	u32 TimeDateStamp;
	u32 ForwarderChain;
	u32 Name;
	u32 FirstThunk;
} Pe32_image_import_directory, Pe64_image_import_directory;

typedef struct {
	u32 Attributes;
	u32 Name;
	u32 ModuleHandle;
	u32 DelayImportAddressTable;
	u32 DelayImportNameTable;
	u32 BoundDelayImportTable;
	u32 UnloadDelayImportTable;
	u32 TimeStamp;
} Pe32_image_delay_import_directory, Pe64_image_delay_import_directory;

typedef struct {
	u32 Signature;
	Pe32_image_file_header file_header;
	Pe32_image_optional_header optional_header;
} Pe32_image_nt_headers;

typedef struct {
	u32 Signature;
	Pe64_image_file_header file_header;
	Pe64_image_optional_header optional_header;
} Pe64_image_nt_headers;

#endif
