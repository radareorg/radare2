/* radare - LGPL - Copyright 2008-2013 nibble, xvilka */

#undef TE_
#undef TE_Word
#undef TE_DWord
#undef TE_VWord

#define TE_Word ut16
#define TE_DWord ut64
#define TE_VWord ut32

#ifndef _INCLUDE_R_BIN_TE_SPECS_H_
#define _INCLUDE_R_BIN_TE_SPECS_H_

#define TE_NAME_LENGTH    256
#define TE_STRING_LENGTH  256

#define TE_IMAGE_FILE_MACHINE_UNKNOWN          0x0000
#define TE_IMAGE_FILE_MACHINE_ALPHA            0x0184
#define TE_IMAGE_FILE_MACHINE_ALPHA64          0x0284
#define TE_IMAGE_FILE_MACHINE_AM33             0x01d3
#define TE_IMAGE_FILE_MACHINE_AMD64            0x8664
#define TE_IMAGE_FILE_MACHINE_ARM              0x01c0
#define TE_IMAGE_FILE_MACHINE_AXP64            TE_IMAGE_FILE_MACHINE_ALPHA64
#define TE_IMAGE_FILE_MACHINE_CEE              0xc0ee
#define TE_IMAGE_FILE_MACHINE_CEF              0x0cef
#define TE_IMAGE_FILE_MACHINE_EBC              0x0ebc
#define TE_IMAGE_FILE_MACHINE_I386             0x014c
#define TE_IMAGE_FILE_MACHINE_IA64             0x0200
#define TE_IMAGE_FILE_MACHINE_M32R             0x9041
#define TE_IMAGE_FILE_MACHINE_M68K             0x0268
#define TE_IMAGE_FILE_MACHINE_MIPS16           0x0266
#define TE_IMAGE_FILE_MACHINE_MIPSFPU          0x0366
#define TE_IMAGE_FILE_MACHINE_MIPSFPU16        0x0466
#define TE_IMAGE_FILE_MACHINE_POWERPC          0x01f0
#define TE_IMAGE_FILE_MACHINE_POWERPCFP        0x01f1
#define TE_IMAGE_FILE_MACHINE_R10000           0x0168
#define TE_IMAGE_FILE_MACHINE_R3000            0x0162
#define TE_IMAGE_FILE_MACHINE_R4000            0x0166
#define TE_IMAGE_FILE_MACHINE_SH3              0x01a2
#define TE_IMAGE_FILE_MACHINE_SH3DSP           0x01a3
#define TE_IMAGE_FILE_MACHINE_SH3E             0x01a4
#define TE_IMAGE_FILE_MACHINE_SH4              0x01a6
#define TE_IMAGE_FILE_MACHINE_SH5              0x01a8
#define TE_IMAGE_FILE_MACHINE_THUMB            0x01c2
#define TE_IMAGE_FILE_MACHINE_TRICORE          0x0520
#define TE_IMAGE_FILE_MACHINE_WCEMIPSV2        0x0169

#define TE_IMAGE_DIRECTORY_ENTRIES                  2

#define TE_IMAGE_DIRECTORY_ENTRY_BASERELOC          0
#define TE_IMAGE_DIRECTORY_ENTRY_DEBUG              1

#define TE_IMAGE_SUBSYSTEM_UNKNOWN                  0
#define TE_IMAGE_SUBSYSTEM_NATIVE                   1
#define TE_IMAGE_SUBSYSTEM_WINDOWS_GUI              2
#define TE_IMAGE_SUBSYSTEM_WINDOWS_CUI              3
#define TE_IMAGE_SUBSYSTEM_POSIX_CUI                7
#define TE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           9
#define TE_IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define TE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define TE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define TE_IMAGE_SUBSYSTEM_EFI_ROM                 13
#define TE_IMAGE_SUBSYSTEM_XBOX                    14


typedef struct {
	ut32 VirtualAddress;
	ut32 Size;
} efi_image_data_directory;

typedef struct {
	ut16 Signature;
	ut16 Machine;
	ut8 NumberOfSections;
	ut8 Subsystem;
	ut16 StrippedSize;
	ut32 AddressOfEntryPoint;
	ut32 BaseOfCode;
	ut64 ImageBase;
	efi_image_data_directory DataDirectory[2];
} TE_image_file_header;

#define TE_IMAGE_SIZEOF_NAME 8

#define TE_IMAGE_SCN_MEM_SHARED    0x10000000
#define TE_IMAGE_SCN_MEM_EXECUTE   0x20000000
#define TE_IMAGE_SCN_MEM_READ      0x40000000
#define TE_IMAGE_SCN_MEM_WRITE     0x80000000

typedef struct {
	ut8  Name[TE_IMAGE_SIZEOF_NAME];
	ut32 VirtualSize;
	ut32 VirtualAddress;
	ut32 SizeOfRawData;
	ut32 PointerToRawData;
	ut32 PointerToRelocations;
	ut32 PointerToLineNumbers;
	ut16 NumberOfRelocations;
	ut16 NumberOfLinenumbers;
	ut32 Characteristics;
} TE_image_section_header;

#endif
