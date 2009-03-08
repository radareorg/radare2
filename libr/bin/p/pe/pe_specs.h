/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_BIN_PE_SPECS_H_
#define _INCLUDE_R_BIN_PE_SPECS_H_

#define PE_Word unsigned short
#define PE_DWord unsigned int
#define PE_Byte unsigned char

#define PE_NAME_LENGTH 64
#define PE_STRING_LENGTH 128

typedef struct {
	PE_Word  e_magic;      /* 00: MZ Header signature */
	PE_Word  e_cblp;       /* 02: Bytes on last page of file */
	PE_Word  e_cp;         /* 04: Pages in file */
	PE_Word  e_crlc;       /* 06: Relocations */
	PE_Word  e_cparhdr;    /* 08: Size of header in paragraphs */
	PE_Word  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
	PE_Word  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
	PE_Word  e_ss;         /* 0e: Initial (relative) SS value */
	PE_Word  e_sp;         /* 10: Initial SP value */
	PE_Word  e_csum;       /* 12: Checksum */
	PE_Word  e_ip;         /* 14: Initial IP value */
	PE_Word  e_cs;         /* 16: Initial (relative) CS value */
	PE_Word  e_lfarlc;     /* 18: File address of relocation table */
	PE_Word  e_ovno;       /* 1a: Overlay number */
	PE_Word  e_res[4];     /* 1c: Reserved words */
	PE_Word  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
	PE_Word  e_oeminfo;    /* 26: OEM information; e_oemid specific */
	PE_Word  e_res2[10];   /* 28: Reserved words */
	PE_DWord e_lfanew;     /* 3c: Offset to extended header */
} pe_image_dos_header;

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
	PE_Word  Machine;
	PE_Word  NumberOfSections;
	PE_DWord TimeDateStamp;
	PE_DWord PointerToSymbolTable;
	PE_DWord NumberOfSymbols;
	PE_Word  SizeOfOptionalHeader;
	PE_Word  Characteristics;
} pe_image_file_header;

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
	PE_DWord VirtualAddress;
	PE_DWord Size;
} pe_image_data_directory;

typedef struct {

	/* Standard fields */

	PE_Word  Magic;
	PE_Byte  MajorLinkerVersion;
	PE_Byte  MinorLinkerVersion;
	PE_DWord SizeOfCode;
	PE_DWord SizeOfInitializedData;
	PE_DWord SizeOfUninitializedData;
	PE_DWord AddressOfEntryPoint;
	PE_DWord BaseOfCode;
	PE_DWord BaseOfData;

	/* NT additional fields */

	PE_DWord ImageBase;
	PE_DWord SectionAlignment;
	PE_DWord FileAlignment;
	PE_Word  MajorOperatingSystemVersion;
	PE_Word  MinorOperatingSystemVersion;
	PE_Word  MajorImageVersion;
	PE_Word  MinorImageVersion;
	PE_Word  MajorSubsystemVersion;
	PE_Word  MinorSubsystemVersion;
	PE_DWord Win32VersionValue;
	PE_DWord SizeOfImage;
	PE_DWord SizeOfHeaders;
	PE_DWord CheckSum;
	PE_Word  Subsystem;
	PE_Word  DllCharacteristics;
	PE_DWord SizeOfStackReserve;
	PE_DWord SizeOfStackCommit;
	PE_DWord SizeOfHeapReserve;
	PE_DWord SizeOfHeapCommit;
	PE_DWord LoaderFlags;
	PE_DWord NumberOfRvaAndSizes;
	pe_image_data_directory DataDirectory[PE_IMAGE_DIRECTORY_ENTRIES];
} pe_image_optional_header;

#define PE_IMAGE_SIZEOF_SHORT_NAME 8

#define PE_IMAGE_SCN_MEM_SHARED    0x10000000
#define PE_IMAGE_SCN_MEM_EXECUTE   0x20000000
#define PE_IMAGE_SCN_MEM_READ      0x40000000
#define PE_IMAGE_SCN_MEM_WRITE     0x80000000

typedef struct {
	PE_Byte  Name[PE_IMAGE_SIZEOF_SHORT_NAME];
	union {
		PE_DWord PhysicalAddress;
		PE_DWord VirtualSize;
	} Misc;
	PE_DWord VirtualAddress;
	PE_DWord SizeOfRawData;
	PE_DWord PointerToRawData;
	PE_DWord PointerToRelocations;
	PE_DWord PointerToLinenumbers;
	PE_Word  NumberOfRelocations;
	PE_Word  NumberOfLinenumbers;
	PE_DWord Characteristics;
} pe_image_section_header;

typedef struct {
	PE_DWord Characteristics;
	PE_DWord TimeDateStamp;
	PE_Word  MajorVersion;
	PE_Word  MinorVersion;
	PE_DWord Name;
	PE_DWord Base;
	PE_DWord NumberOfFunctions;
	PE_DWord NumberOfNames;
	PE_DWord AddressOfFunctions;
	PE_DWord AddressOfNames;
	PE_DWord AddressOfOrdinals;
} pe_image_export_directory;

typedef struct {
	PE_DWord Characteristics;
	PE_DWord TimeDateStamp;
	PE_DWord ForwarderChain;
	PE_DWord Name;
	PE_DWord FirstThunk;
} pe_image_import_directory;

typedef struct {
	PE_DWord Attributes;
	PE_DWord Name;
	PE_DWord ModuleHandle;
	PE_DWord DelayImportAddressTable;
	PE_DWord DelayImportNameTable;
	PE_DWord BoundDelayImportTable;
	PE_DWord UnloadDelayImportTable;
	PE_DWord TimeStamp;
} pe_image_delay_import_directory;

typedef struct {
	PE_DWord Signature;
	pe_image_file_header file_header;
	pe_image_optional_header optional_header;
} pe_image_nt_headers;

#endif
