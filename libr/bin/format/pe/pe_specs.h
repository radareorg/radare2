/* radare - LGPL - Copyright 2008 nibble */

#undef PE_
#undef ILT_MASK1
#undef ILT_MASK2
#undef PE_Word
#undef PE_DWord
#undef PE_VWord
#undef R_BUF_READ_PE_DWORD_AT
#undef PE_DWORD_MAX

#ifdef R_BIN_PE64
#define PE_(name) Pe64_ ## name
#define ILT_MASK1 0x8000000000000000LL
#define ILT_MASK2 0x7fffffffffffffffLL
#define PE_Word ut16
#define PE_DWord ut64
#define PE_VWord ut32
#define R_BUF_READ_PE_DWORD_AT r_buf_read_le64_at
#define PE_DWORD_MAX UT64_MAX
#else
#define PE_(name) Pe32_ ## name
#define ILT_MASK1 0x80000000
#define ILT_MASK2 0x7fffffff
#define PE_Word ut16
#define PE_DWord ut32
#define PE_VWord ut32
#define R_BUF_READ_PE_DWORD_AT r_buf_read_le32_at
#define PE_DWORD_MAX UT32_MAX
#endif

#ifndef _INCLUDE_R_BIN_PE_SPECS_H_
#define _INCLUDE_R_BIN_PE_SPECS_H_

#define PE_NAME_LENGTH 256
#define PE_STRING_LENGTH 256

typedef struct {
	ut16 e_magic;      /* 00: MZ Header signature */
	ut16 e_cblp;       /* 02: Bytes on last page of file */
	ut16 e_cp;         /* 04: Pages in file */
	ut16 e_crlc;       /* 06: Relocations */
	ut16 e_cparhdr;    /* 08: Size of header in paragraphs */
	ut16 e_minalloc;   /* 0a: Minimum extra paragraphs needed */
	ut16 e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
	ut16 e_ss;         /* 0e: Initial (relative) SS value */
	ut16 e_sp;         /* 10: Initial SP value */
	ut16 e_csum;       /* 12: Checksum */
	ut16 e_ip;         /* 14: Initial IP value */
	ut16 e_cs;         /* 16: Initial (relative) CS value */
	ut16 e_lfarlc;     /* 18: File address of relocation table */
	ut16 e_ovno;       /* 1a: Overlay number */
	ut16 e_res[4];     /* 1c: Reserved words */
	ut16 e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
	ut16 e_oeminfo;    /* 26: OEM information; e_oemid specific */
	ut16 e_res2[10];   /* 28: Reserved words */
	ut32 e_lfanew;     /* 3c: Offset to extended header */
} Pe32_image_dos_header, Pe64_image_dos_header;

#define PE_IMAGE_FILE_TYPE_PE32                0x10b
#define PE_IMAGE_FILE_TYPE_PE32PLUS            0x20b

#define PE_IMAGE_FILE_MACHINE_UNKNOWN          0x0000
#define PE_IMAGE_FILE_MACHINE_ALPHA            0x0184
#define PE_IMAGE_FILE_MACHINE_ALPHA64          0x0284
#define PE_IMAGE_FILE_MACHINE_AM33             0x01d3
#define PE_IMAGE_FILE_MACHINE_AMD64            0x8664
#define PE_IMAGE_FILE_MACHINE_ARM              0x01c0
#define PE_IMAGE_FILE_MACHINE_ARM64            0xaa64
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
#define PE_IMAGE_FILE_MACHINE_RISCV32          0x5032
#define PE_IMAGE_FILE_MACHINE_RISCV64          0x5064
#define PE_IMAGE_FILE_MACHINE_RISCV128         0x5128

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

#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA        0x0020
#define IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE          0x0040
#define IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY       0x0080
#define IMAGE_DLL_CHARACTERISTICS_NX_COMPAT             0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                 0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND                0x0800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER           0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF               0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  0x8000

#define IMAGE_DEBUG_TYPE_CODEVIEW 2
#define IMAGE_DEBUG_TYPE_MISC 4

typedef struct {
	ut16 Machine;
	ut16 NumberOfSections;
	ut32 TimeDateStamp;
	ut32 PointerToSymbolTable;
	ut32 NumberOfSymbols;
	ut16 SizeOfOptionalHeader;
	ut16 Characteristics;
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

//language

#define PE_LANG_NEUTRAL       0x00
#define PE_LANG_INVARIANT     0x7f
#define PE_LANG_AFRIKAANS     0x36
#define PE_LANG_ALBANIAN      0x1c
#define PE_LANG_ARABIC        0x01
#define PE_LANG_ARMENIAN      0x2b
#define PE_LANG_ASSAMESE      0x4d
#define PE_LANG_AZERI         0x2c
#define PE_LANG_BASQUE        0x2d
#define PE_LANG_BELARUSIAN    0x23
#define PE_LANG_BENGALI       0x45
#define PE_LANG_BULGARIAN     0x02
#define PE_LANG_CATALAN       0x03
#define PE_LANG_CHINESE       0x04
#define PE_LANG_CROATIAN      0x1a
#define PE_LANG_CZECH         0x05
#define PE_LANG_DANISH        0x06
#define PE_LANG_DIVEHI        0x65
#define PE_LANG_DUTCH         0x13
#define PE_LANG_ENGLISH       0x09
#define PE_LANG_ESTONIAN      0x25
#define PE_LANG_FAEROESE      0x38
#define PE_LANG_FARSI         0x29
#define PE_LANG_FINNISH       0x0b
#define PE_LANG_FRENCH        0x0c
#define PE_LANG_GALICIAN      0x56
#define PE_LANG_GEORGIAN      0x37
#define PE_LANG_GERMAN        0x07
#define PE_LANG_GREEK         0x08
#define PE_LANG_GUJARATI      0x47
#define PE_LANG_HEBREW        0x0d
#define PE_LANG_HINDI         0x39
#define PE_LANG_HUNGARIAN     0x0e
#define PE_LANG_ICELANDIC     0x0f
#define PE_LANG_INDONESIAN    0x21
#define PE_LANG_ITALIAN       0x10
#define PE_LANG_JAPANESE      0x11
#define PE_LANG_KANNADA       0x4b
#define PE_LANG_KASHMIRI      0x60
#define PE_LANG_KAZAK         0x3f
#define PE_LANG_KONKANI       0x57
#define PE_LANG_KOREAN        0x12
#define PE_LANG_KYRGYZ        0x40
#define PE_LANG_LATVIAN       0x26
#define PE_LANG_LITHUANIAN    0x27
#define PE_LANG_MACEDONIAN    0x2f
#define PE_LANG_MALAY         0x3e
#define PE_LANG_MALAYALAM     0x4c
#define PE_LANG_MANIPURI      0x58
#define PE_LANG_MARATHI       0x4e
#define PE_LANG_MONGOLIAN     0x50
#define PE_LANG_NEPALI        0x61
#define PE_LANG_NORWEGIAN     0x14
#define PE_LANG_ORIYA         0x48
#define PE_LANG_POLISH        0x15
#define PE_LANG_PORTUGUESE    0x16
#define PE_LANG_PUNJABI       0x46
#define PE_LANG_ROMANIAN      0x18
#define PE_LANG_RUSSIAN       0x19
#define PE_LANG_SANSKRIT      0x4f
#define PE_LANG_SERBIAN       0x1a
#define PE_LANG_SINDHI        0x59
#define PE_LANG_SLOVAK        0x1b
#define PE_LANG_SLOVENIAN     0x24
#define PE_LANG_SPANISH       0x0a
#define PE_LANG_SWAHILI       0x41
#define PE_LANG_SWEDISH       0x1d
#define PE_LANG_SYRIAC        0x5a
#define PE_LANG_TAMIL         0x49
#define PE_LANG_TATAR         0x44
#define PE_LANG_TELUGU        0x4a
#define PE_LANG_THAI          0x1e
#define PE_LANG_TURKISH       0x1f
#define PE_LANG_UKRAINIAN     0x22
#define PE_LANG_URDU          0x20
#define PE_LANG_UZBEK         0x43
#define PE_LANG_VIETNAMESE    0x2a
#define PE_LANG_GAELIC        0x3c
#define PE_LANG_MALTESE       0x3a
#define PE_LANG_MAORI         0x28
#define PE_LANG_RHAETO_ROMANCE 0x17
#define PE_LANG_SAAMI         0x3b
#define PE_LANG_SORBIAN       0x2e
#define PE_LANG_SUTU          0x30
#define PE_LANG_TSONGA        0x31
#define PE_LANG_TSWANA        0x32
#define PE_LANG_VENDA         0x33
#define PE_LANG_XHOSA         0x34
#define PE_LANG_ZULU          0x35
#define PE_LANG_ESPERANTO     0x8f
#define PE_LANG_WALON         0x90
#define PE_LANG_CORNISH       0x91
#define PE_LANG_WELSH         0x92
#define PE_LANG_BRETON        0x93

typedef struct {
	ut32 VirtualAddress;
	ut32 Size;
} Pe32_image_data_directory, Pe64_image_data_directory;

typedef struct {
	/* Standard fields */
	ut16 Magic;
	ut8 MajorLinkerVersion;
	ut8 MinorLinkerVersion;
	ut32 SizeOfCode;
	ut32 SizeOfInitializedData;
	ut32 SizeOfUninitializedData;
	ut32 AddressOfEntryPoint;
	ut32 BaseOfCode;
	ut32 BaseOfData;
	/* NT additional fields */
	ut32 ImageBase;
	ut32 SectionAlignment;
	ut32 FileAlignment;
	ut16 MajorOperatingSystemVersion;
	ut16 MinorOperatingSystemVersion;
	ut16 MajorImageVersion;
	ut16 MinorImageVersion;
	ut16 MajorSubsystemVersion;
	ut16 MinorSubsystemVersion;
	ut32 Win32VersionValue;
	ut32 SizeOfImage;
	ut32 SizeOfHeaders;
	ut32 CheckSum;
	ut16 Subsystem;
	ut16 DllCharacteristics;
	ut32 SizeOfStackReserve;
	ut32 SizeOfStackCommit;
	ut32 SizeOfHeapReserve;
	ut32 SizeOfHeapCommit;
	ut32 LoaderFlags;
	ut32 NumberOfRvaAndSizes;
	Pe32_image_data_directory DataDirectory[PE_IMAGE_DIRECTORY_ENTRIES];
} Pe32_image_optional_header;

typedef struct {
	/* Standard fields */
	ut16 Magic;
	ut8 MajorLinkerVersion;
	ut8 MinorLinkerVersion;
	ut32 SizeOfCode;
	ut32 SizeOfInitializedData;
	ut32 SizeOfUninitializedData;
	ut32 AddressOfEntryPoint;
	ut32 BaseOfCode;
	/* NT additional fields */
	ut64 ImageBase;
	ut32 SectionAlignment;
	ut32 FileAlignment;
	ut16 MajorOperatingSystemVersion;
	ut16 MinorOperatingSystemVersion;
	ut16 MajorImageVersion;
	ut16 MinorImageVersion;
	ut16 MajorSubsystemVersion;
	ut16 MinorSubsystemVersion;
	ut32 Win32VersionValue;
	ut32 SizeOfImage;
	ut32 SizeOfHeaders;
	ut32 CheckSum;
	ut16 Subsystem;
	ut16 DllCharacteristics;
	ut64 SizeOfStackReserve;
	ut64 SizeOfStackCommit;
	ut64 SizeOfHeapReserve;
	ut64 SizeOfHeapCommit;
	ut32 LoaderFlags;
	ut32 NumberOfRvaAndSizes;
	Pe64_image_data_directory DataDirectory[PE_IMAGE_DIRECTORY_ENTRIES];
} Pe64_image_optional_header;

typedef struct {
	ut32 HeaderSize;
	ut16 MajorRuntimeVersion;
	ut16 MinorRuntimeVersion;
	ut32 MetaDataDirectoryAddress;
	ut32 MetaDataDirectorySize;
	ut32 Flags;
	ut32 EntryPointToken;
	ut32 ResourcesDirectoryAddress;
	ut32 ResourcesDirectorySize;
	ut32 StrongNameSignatureAddress;
	ut32 StrongNameSignatureSize;
	ut32 CodeManagerTableAddress;
	ut32 CodeManagerTableSize;
	ut32 VTableFixupsAddress;
	ut32 VTableFixupsSize;
	ut32 ExportAddressTableJumpsAddress;
	ut32 ExportAddressTableJumpsSize;
	ut32 ManagedNativeHeaderAddress;
	ut32 ManagedNativeHeaderSize;
} Pe32_image_clr_header, Pe64_image_clr_header;

typedef struct {
	ut64 Signature;
	ut16 MajorVersion;
	ut16 MinorVersion;
	ut32 Reserved;
	ut32 VersionStringLength;
	char* VersionString;
	ut16 Flags;
	ut16 NumberOfStreams;
} Pe32_image_metadata_header, Pe64_image_metadata_header;

typedef struct {
	ut32 Offset;
	ut32 Size;
	char* Name;
} Pe32_image_metadata_stream, Pe64_image_metadata_stream;

typedef struct {
	ut16 productId;
	ut16 minVersion;
	ut32 timesUsed;
	char *productName;
} Pe_image_rich_entry;

#define PE_IMAGE_SIZEOF_SHORT_NAME 8

#define PE_IMAGE_SCN_MEM_SHARED    0x10000000
#define PE_IMAGE_SCN_MEM_EXECUTE   0x20000000
#define PE_IMAGE_SCN_MEM_READ      0x40000000
#define PE_IMAGE_SCN_MEM_WRITE     0x80000000

typedef struct {
	ut8 Name[PE_IMAGE_SIZEOF_SHORT_NAME];
	union {
		ut32 PhysicalAddress;
		ut32 VirtualSize;
	} Misc;
	ut32 VirtualAddress;
	ut32 SizeOfRawData;
	ut32 PointerToRawData;
	ut32 PointerToRelocations;
	ut32 PointerToLinenumbers;
	ut16 NumberOfRelocations;
	ut16 NumberOfLinenumbers;
	ut32 Characteristics;
} Pe32_image_section_header, Pe64_image_section_header;

typedef struct {
	ut32 Characteristics;
	ut32 TimeDateStamp;
	ut16 MajorVersion;
	ut16 MinorVersion;
	ut32 Name;
	ut32 Base;
	ut32 NumberOfFunctions;
	ut32 NumberOfNames;
	ut32 AddressOfFunctions;
	ut32 AddressOfNames;
	ut32 AddressOfOrdinals;
} Pe32_image_export_directory, Pe64_image_export_directory;

typedef struct {
	ut32 Characteristics;
	ut32 TimeDateStamp;
	ut32 ForwarderChain;
	ut32 Name;
	ut32 FirstThunk;
} Pe32_image_import_directory, Pe64_image_import_directory;

typedef struct {
	ut32 Attributes;
	ut32 Name;
	ut32 ModulePlugin;
	ut32 DelayImportAddressTable;
	ut32 DelayImportNameTable;
	ut32 BoundDelayImportTable;
	ut32 UnloadDelayImportTable;
	ut32 TimeStamp;
} Pe32_image_delay_import_directory, Pe64_image_delay_import_directory;

typedef struct {
	ut32 StartAddressOfRawData;
	ut32 EndAddressOfRawData;
	ut32 AddressOfIndex;
	ut32 AddressOfCallBacks;
	ut32 SizeOfZeroFill;
	ut32 Characteristics;
} Pe32_image_tls_directory, Pe64_image_tls_directory;

typedef struct {
	ut32 dwLength;
	ut16 wRevision;
	ut16 wCertificateType;
	ut8 *bCertificate;
} Pe_certificate;

typedef struct {
	ut32 length;
	Pe_certificate **certificates;
} Pe_image_security_directory;

#define PE_WIN_CERT_REVISION_1_0	0x0100
#define PE_WIN_CERT_REVISION_2_0	0x0200

#define PE_WIN_CERT_TYPE_X509			0x0001
#define PE_WIN_CERT_TYPE_PKCS_SIGNED_DATA	0x0002
#define PE_WIN_CERT_TYPE_RESERVED_1		0x0003
#define PE_WIN_CERT_TYPE_TS_STACK_SIGNED	0x0004

typedef struct {
	ut32 Signature;
	Pe32_image_file_header file_header;
	Pe32_image_optional_header optional_header;
} Pe32_image_nt_headers;

typedef struct {
	ut32 Signature;
	Pe64_image_file_header file_header;
	Pe64_image_optional_header optional_header;
} Pe64_image_nt_headers;

typedef struct {
	ut32 Characteristics;
	ut32 TimeDateStamp;
	ut16 MajorVersion;
	ut16 MinorVersion;
	ut32 Type;
	ut32 SizeOfData;
	ut32 AddressOfRawData;
	ut32 PointerToRawData;
} Pe32_image_debug_directory_entry, Pe64_image_debug_directory_entry;

typedef struct {
	ut32 Characteristics;
	ut32 TimeDateStamp;
	ut16 MajorVersion;
	ut16 MinorVersion;
	ut16 NumberOfNamedEntries;
	ut16 NumberOfIdEntries;
} Pe_image_resource_directory;

typedef struct {
	union {
		// struct {
		// 	ut32 NameOffset: 31;
		// 	ut32 NameIsString: 1;
		// } s;
		// ut16 Id;
		ut32 Name;
	} u1;
	union {
		// struct {
		// 	ut32 OffsetToDirectory: 31;
		// 	ut32 DataIsDirectory: 1;
		// } s;
		ut32 OffsetToData;
	} u2;
} Pe_image_resource_directory_entry;

// Pe_image_resource_directory_string is unused. Did not find any PE with ASCII resource name.
// Refer to https://msdn.microsoft.com/en-us/library/ms809762.aspx
// "Peering Inside the PE: A Tour of the Win32 Portable Executable File Format"
// "Yes, even PE files intended for non-UNICODE Win32 implementations use UNICODE here."
typedef struct {
	ut16 Length;
	char* NameString;
} Pe_image_resource_directory_string;

typedef struct {
	ut16 Length;
	ut16* NameString;
} Pe_image_resource_directory_string_u;

typedef struct {
	ut32 OffsetToData;
	ut32 Size;
	ut32 CodePage;
	ut32 Reserved;
} Pe_image_resource_data_entry;


//resource types
#define R_PE_MAX_RESOURCES 2056
#define PE_RESOURCE_ENTRY_CURSOR          1
#define PE_RESOURCE_ENTRY_BITMAP          2
#define PE_RESOURCE_ENTRY_ICON            3
#define PE_RESOURCE_ENTRY_MENU            4
#define PE_RESOURCE_ENTRY_DIALOG          5
#define PE_RESOURCE_ENTRY_STRING          6
#define PE_RESOURCE_ENTRY_FONTDIR         7
#define PE_RESOURCE_ENTRY_FONT            8
#define PE_RESOURCE_ENTRY_ACCELERATOR     9
#define PE_RESOURCE_ENTRY_RCDATA         10
#define PE_RESOURCE_ENTRY_MESSAGETABLE   11
#define PE_RESOURCE_ENTRY_GROUP_CURSOR   12
#define PE_RESOURCE_ENTRY_GROUP_ICON     14
#define PE_RESOURCE_ENTRY_VERSION        16
#define PE_RESOURCE_ENTRY_DLGINCLUDE     17
#define PE_RESOURCE_ENTRY_PLUGPLAY       19
#define PE_RESOURCE_ENTRY_VXD            20
#define PE_RESOURCE_ENTRY_ANICURSOR      21
#define PE_RESOURCE_ENTRY_ANIICON        22
#define PE_RESOURCE_ENTRY_HTML           23
#define PE_RESOURCE_ENTRY_MANIFEST       24

#define STRINGFILEINFO_TEXT  "StringFileInfo"
#define TRANSLATION_TEXT     "Translation"
#define VARFILEINFO_TEXT     "VarFileInfo"
#define VS_VERSION_INFO_TEXT "VS_VERSION_INFO"

#define STRINGFILEINFO_TEXT_LEN  sizeof(STRINGFILEINFO_TEXT)
#define TRANSLATION_TEXT_LEN     sizeof(TRANSLATION_TEXT)
#define VARFILEINFO_TEXT_LEN     sizeof(VARFILEINFO_TEXT)
#define VS_VERSION_INFO_TEXT_LEN sizeof(VS_VERSION_INFO_TEXT)

#define EIGHT_HEX_DIG_UTF_16_LEN ((8 + 1) * 2)

#define STRINGFILEINFO_UTF_16  "S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0"
#define TRANSLATION_UTF_16     "T\0r\0a\0n\0s\0l\0a\0t\0i\0o\0n\0\0"
#define VARFILEINFO_UTF_16     "V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0"
#define VS_VERSION_INFO_UTF_16 "V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0"

#define STRINGFILEINFO_UTF_16_LEN  sizeof (STRINGFILEINFO_UTF_16)
#define TRANSLATION_UTF_16_LEN     sizeof (TRANSLATION_UTF_16)
#define VARFILEINFO_UTF_16_LEN     sizeof (VARFILEINFO_UTF_16)
#define VS_VERSION_INFO_UTF_16_LEN sizeof (VS_VERSION_INFO_UTF_16)

typedef struct {
	ut16 wLength; //The length, in bytes, of this String structure.
	ut16 wValueLength; //The size, in words, of the Value member.
	ut16 wType; //1 text; 0 binary
	ut16 wKeyLen;
	ut16* szKey; //An arbitrary Unicode string
	//ut16 Padding;
	ut16* Value; //A zero-terminated string.
} String;

typedef struct {
	ut16 wLength; //The length, in bytes, of this StringTable structure, including all structures indicated by the Children member.
	ut16 wValueLength; //always 0
	ut16 wType; //1 text; 0 binary
	ut16* szKey;
	//An 8-digit hexadecimal number stored as a Unicode string.
	//The four most significant digits represent the language identifier.
	//The four least significant digits represent the code page for which the data is formatted
	//ut16 Padding;
	ut32 numOfChildren;
	String** Children; //An array of one or more String structures
} StringTable;

typedef struct {
	ut16 wLength; //The length, in bytes, of the entire StringFileInfo block, including all structures indicated by the Children member.
	ut16 wValueLength; //always 0
	ut16 wType; //1 text; 0 binary
	ut16* szKey; //L"StringFileInfo"
	//ut16 Padding;
	ut32 numOfChildren;
	StringTable** Children; //An array of one or more StringTable structures
} StringFileInfo;

typedef struct {
	ut16 wLength; //The length, in bytes, of the Var structure. (with pad)
	ut16 wValueLength; //The length, in bytes, of the Value member.
	ut16 wType; //1 text; 0 binary
	ut16* szKey; //L"Translation"
	//ut16 Padding;
	ut32 numOfValues;
	ut32* Value; //An array of one or more values that are language and code page identifier pairs
} Var;

typedef struct {
	ut16 wLength; //The length, in bytes, of the entire VarFileInfo block, including all structures indicated by the Children member. (with pad)
	ut16 wValueLength; //always 0
	ut16 wType; //1 text; 0 binary
	ut16* szKey; //L"VarFileInfo"
	//ut16 Padding;
	ut32 numOfChildren;
	Var** Children; //Typically contains a list of languages that the application or DLL supports.
} VarFileInfo;

#define PE_VS_FF_DEBUG        0x00000001L
#define PE_VS_FF_PRERELEASE   0x00000002L
#define PE_VS_FF_PATCHED      0x00000004L
#define PE_VS_FF_PRIVATEBUILD 0x00000008L
#define PE_VS_FF_INFOINFERRED 0x00000010L
#define PE_VS_FF_SPECIALBUILD 0x00000020L

#define PE_VOS_DOS        0x00010000L
#define PE_VOS_NT         0x00040000L
#define PE_VOS__WINDOWS16 0x00000001L
#define PE_VOS__WINDOWS32 0x00000004L
#define PE_VOS_OS216      0x00020000L
#define PE_VOS_OS232      0x00030000L
#define PE_VOS__PM16      0x00000002L
#define PE_VOS__PM32      0x00000003L
#define PE_VOS_UNKNOWN    0x00000000L

#define PE_VOS_DOS_WINDOWS16 0x00010001L
#define PE_VOS_DOS_WINDOWS32 0x00010004L
#define PE_VOS_NT_WINDOWS32  0x00040004L
#define PE_VOS_OS216_PM16    0x00020002L
#define PE_VOS_OS232_PM32    0x00030003L

#define PE_VFT_APP        0x00000001L
#define PE_VFT_DLL        0x00000002L
#define PE_VFT_DRV        0x00000003L
#define PE_VFT_FONT       0x00000004L
#define PE_VFT_STATIC_LIB 0x00000007L
#define PE_VFT_UNKNOWN    0x00000000L
#define PE_VFT_VXD        0x00000005L

#define PE_VFT2_DRV_COMM              0x0000000AL
#define PE_VFT2_DRV_DISPLAY           0x00000004L
#define PE_VFT2_DRV_INSTALLABLE       0x00000008L
#define PE_VFT2_DRV_KEYBOARD          0x00000002L
#define PE_VFT2_DRV_LANGUAGE          0x00000003L
#define PE_VFT2_DRV_MOUSE             0x00000005L
#define PE_VFT2_DRV_NETWORK           0x00000006L
#define PE_VFT2_DRV_PRINTER           0x00000001L
#define PE_VFT2_DRV_SOUND             0x00000009L
#define PE_VFT2_DRV_SYSTEM            0x00000007L
#define PE_VFT2_DRV_VERSIONED_PRINTER 0x0000000CL
#define PE_VFT2_UNKNOWN               0x00000000L

#define PE_VFT2_FONT_RASTER   0x00000001L
#define PE_VFT2_FONT_TRUETYPE 0x00000003L
#define PE_VFT2_FONT_VECTOR   0x00000002L
#define PE_VFT2_UNKNOWN       0x00000000L

typedef struct {
	ut32 dwSignature; //Contains the value 0xFEEF04BD
	ut32 dwStrucVersion;
	ut32 dwFileVersionMS;
	ut32 dwFileVersionLS;
	ut32 dwProductVersionMS;
	ut32 dwProductVersionLS;
	ut32 dwFileFlagsMask;
	ut32 dwFileFlags;
	ut32 dwFileOS;
	ut32 dwFileType;
	ut32 dwFileSubtype;
	ut32 dwFileDateMS;
	ut32 dwFileDateLS;
} PE_VS_FIXEDFILEINFO;

typedef struct {
	ut16 wLength;             //whole structure size (padding not included (in case of multiply version info structures))
	ut16 wValueLength;             //if 0 there is no Value
	ut16 wType;             //1 text; 0 binary
	ut16* szKey;             //L"VS_VERSION_INFO"
	//ut16             Padding1; //pad for 32 boundary
	PE_VS_FIXEDFILEINFO* Value;
	//ut16             Padding2; //pad for 32 boundary
	VarFileInfo* varFileInfo;      //0 or 1 elements
	StringFileInfo* stringFileInfo;   //0 or 1 elements
} PE_VS_VERSIONINFO;

// Specific for x64 SEH

typedef enum {
	UWOP_PUSH_NONVOL = 0, /* info == register number */
	UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
	UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
	UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
	UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
	UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
	UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
	UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
	UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} PE64_UNWIND_CODE_OPS;

#define PE64_UNW_FLAG_NHANDLER 0
#define PE64_UNW_FLAG_EHANDLER 1
#define PE64_UNW_FLAG_UHANDLER 2
#define PE64_UNW_FLAG_CHAININFO 4

typedef struct {
	ut32 BeginAddress; // Function start address
	ut32 EndAddress; // Function end address
	union {
		ut32 UnwindInfoAddress;
		ut32 UnwindData;
	};
} PE64_RUNTIME_FUNCTION;

typedef union {
	struct {
		ut8 CodeOffset;
		ut8 UnwindOp : 4;
		ut8 OpInfo : 4;
	};
	ut16 FrameOffset;
} PE64_UNWIND_CODE;

typedef struct {
	ut8 Version : 3;
	ut8 Flags : 5;
	ut8 SizeOfProlog;
	ut8 CountOfCodes;
	ut8 FrameRegister : 4;
	ut8 FrameOffset : 4;
	PE64_UNWIND_CODE UnwindCode[];
	/*
	union {
		ut32 ExceptionHandler; // if (flags & UNW_FLAG_EHANDLER)
		PE64_RUNTIME_FUNCTION FunctionEntry;    // else if (flags & UNW_FLAG_CHAININFO)
	};
	ut32 ExceptionData[]; // if (flags & UNW_FLAG_EHANDLER)
	*/
} PE64_UNWIND_INFO;

typedef struct {
	ut32 BeginAddress;
	ut32 EndAddress;
	ut32 HandlerAddress;
	ut32 JumpTarget;
} PE64_SCOPE_RECORD;

typedef struct {
	ut32 Count;
	PE64_SCOPE_RECORD ScopeRecord[];
} PE64_SCOPE_TABLE;

int Pe32_read_dos_header(RBuffer *b, Pe32_image_dos_header *header);
int Pe32_read_nt_headers(RBuffer *b, ut64 addr, Pe32_image_nt_headers *headers);
int Pe32_read_image_section_header(RBuffer *b, ut64 addr, Pe32_image_section_header *section_header);
void Pe32_write_image_section_header(RBuffer *b, ut64 addr, Pe32_image_section_header *section_header);

int Pe64_read_dos_header(RBuffer *b, Pe64_image_dos_header *header);
int Pe64_read_nt_headers(RBuffer *b, ut64 addr, Pe64_image_nt_headers *headers);
int Pe64_read_image_section_header(RBuffer *b, ut64 addr, Pe64_image_section_header *section_header);
void Pe64_write_image_section_header(RBuffer *b, ut64 addr, Pe64_image_section_header *section_header);

#endif
