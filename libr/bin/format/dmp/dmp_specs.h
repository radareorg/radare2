/* radare2 - LGPL - Copyright 2020 - abcSup */

#ifndef DMP_SPECS_H
#define DMP_SPECS_H

#include <r_types_base.h>

#include "mdmp/mdmp_specs.h"
#include "mdmp/mdmp_windefs.h"

#define DMP64_MAGIC		"\x50\x41\x47\x45\x44\x55\x36\x34" // PAGEDU64
#define DMP_BMP_MAGIC		"\x53\x44\x4d\x50\x44\x55\x4d\x50" // SDMPDUMP
#define DMP_UNUSED_MAGIC	"\x50\x41\x47\x45" // PAGE

#define DMP_DUMPTYPE_UNKNOWN		0
#define DMP_DUMPTYPE_FULL		1
#define DMP_DUMPTYPE_SUMMARY		2
#define DMP_DUMPTYPE_HEADER		3
#define DMP_DUMPTYPE_TRIAGE		4
#define DMP_DUMPTYPE_BITMAPFULL	5
#define DMP_DUMPTYPE_BITMAPKERNEL	6
#define DMP_DUMPTYPE_AUTOMATIC		7

#define DMP_PAGE_SIZE	0x1000

typedef struct _PHYSICAL_MEMORY_RUN {
    ut64 BasePage;
    ut64 PageCount;
} dmp_p_memory_run;

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR32 {
	ut32 NumberOfRuns;
	ut32 NumberOfPages;
	dmp_p_memory_run Run[1];
} dmp32_p_memory_desc;

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR64 {
	ut32 NumberOfRuns; // 0x0
	ut32 _padding1;
	ut64 NumberOfPages; // 0x8
	dmp_p_memory_run Run[1];
} dmp64_p_memory_desc;

typedef struct {
	ut8 Signature[4];
	ut8 ValidDump[4];
	ut32 MajorVersion;
	ut32 MinorVersion;
	ut32 DirectoryTableBase;
	ut32 PfnDataBase;
	ut32 PsLoadedModuleList;
	ut32 PsActiveProcessHead;
	ut32 MachineImageType;
	ut32 NumberProcessors;
	ut32 BugCheckCode;
	ut32 BugCheckCodeParameter[4];
	ut8 VersionUser[32];
	ut8 PaeEnabled;
	ut8 KdSecondaryVersion;
	ut8 VersionUser2[2];
	ut32 KdDebuggerDataBlock;
	dmp32_p_memory_desc PhysicalMemoryBlockBuffer;
	struct context_type_i386 ContextRecord; // 0x320 0x2cc bytes
	ut8 _padding1[0x1e4];
	struct windows_exception_record32 Exception; // 0x7d0
	ut8 Comment[128];
	ut32 DumpType;
	ut32 MiniDumpFields;
	ut32 SecondaryDataState;
	ut32 ProductType;
	ut32 SuiteMask;
	ut32 WriterStatus;
	ut64 RequiredDumpSpace;
	ut64 SystemUpTime;
	ut64 SystemTime;
	ut8 reserved3[56];
} dmp32_header;

typedef struct {
	ut8 Signature[4];
	ut8 ValidDump[4];
	ut32 MajorVersion;
	ut32 MinorVersion;
	ut64 DirectoryTableBase;
	ut64 PfnDataBase;
	ut64 PsLoadedModuleList;
	ut64 PsActiveProcessHead;
	ut32 MachineImageType;
	ut32 NumberProcessors;
	ut32 BugCheckCode; // 0x38
	ut8 _padding1[0x4];
	ut64 BugCheckCodeParameter[4]; // 0x40
	ut8 _padding2[0x20];
	ut64 KdDebuggerDataBlock; // 0x80
	dmp64_p_memory_desc PhysicalMemoryBlockBuffer; // 0x88 0x20 bytes
	ut8 _padding3[0x2a0];
	struct context_type_amd64 ContextRecord; // 0x348 0x4d0 bytes
	ut8 _padding4[0x6e8];
	struct windows_exception_record64 Exception; // 0xf00 0x98 bytes
	ut32 DumpType; // 0xf98 0x4 bytes
	ut8 _padding5[0x4];
	ut64 RequiredDumpSpace; //0xfa0
	ut64 SystemTime;
	ut8 Comment[128];
	ut64 SystemUpTime;
	ut32 MiniDumpFields;
	ut32 SecondaryDataState;
	ut32 ProductType;
	ut32 SuiteMask;
	ut32 WriterStatus;
	ut8 Unused1;
	ut8 KdSecondaryVersion;
	ut8 Unused[2];
	ut8 _reserved0[4016];
} dmp64_header;

typedef struct {
	ut8 Signature[4];
	ut8 ValidDump[4];
	ut8 _padding1[0x18];
	ut64 FirstPage;
	ut64 TotalPresentPages;
	ut64 Pages;
	ut8 Bitmap[1];
} dmp_bmp_header;

#endif /* DMP_SPECS_H */
