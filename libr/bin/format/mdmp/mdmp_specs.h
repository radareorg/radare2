#ifndef MDMP_SPECS_H
#define MDMP_SPECS_H

#define MDMP_PLATFORM_PURE(NAME, ARCH) NAME ## _ ## ARCH
#define MDMP_PLATFORM(NAME, ARCH) MDMP_PLATFORM_PURE(NAME, ARCH)

#define MINIDUMP_SIGNATURE 0x504d444d /* PMDM */

typedef DWORD RVA;
typedef ULONG64 RVA64;


typedef struct _MINIDUMP_HEADER {
	ULONG32 Signature;
	ULONG32 Version;
	ULONG32 NumberOfStreams;
	RVA StreamDirectoryRva;
	ULONG32 CheckSum;
	ULONG32 TimeDateStamp;
	ULONG64 Flags;
} MINIDUMP_HEADER, *PMINIDUMP_HEADER;


typedef struct _MINIDUMP_LOCATION_DESCRIPTOR {
	ULONG32 DataSize;
	RVA Rva;
} MINIDUMP_LOCATION_DESCRIPTOR;

typedef struct _MINIDUMP_LOCATION_DESCRIPTOR64 {
	ULONG64 DataSize;
	RVA64 Rva;
} MINIDUMP_LOCATION_DESCRIPTOR64;


typedef struct _MINIDUMP_MEMORY_DESCRIPTOR {
	ULONG64 StartOfMemoryRange;
	MINIDUMP_LOCATION_DESCRIPTOR Memory;
} MINIDUMP_MEMORY_DESCRIPTOR, *PMINIDUMP_MEMORY_DESCRIPTOR;

typedef struct _MINIDUMP_MEMORY_DESCRIPTOR64 {
	ULONG64 StartOfMemoryRange;
	ULONG64 DataSize;
} MINIDUMP_MEMORY_DESCRIPTOR64, *PMINIDUMP_MEMORY_DESCRIPTOR64;


typedef enum _MINIDUMP_STREAM_TYPE {

	UnusedStream			= 0,
	ReservedStream0			= 1,
	ReservedStream1			= 2,
	ThreadListStream			= 3,
	ModuleListStream			= 4,
	MemoryListStream			= 5,
	ExceptionStream			= 6,
	SystemInfoStream			= 7,
	ThreadExListStream			= 8,
	Memory64ListStream			= 9,
	CommentStreamA			= 10,
	CommentStreamW			= 11,
	HandleDataStream			= 12,
	FunctionTableStream			= 13,
	UnloadedModuleListStream		= 14,
	MiscInfoStream			= 15,
	MemoryInfoListStream		= 16,
	ThreadInfoListStream		= 17,
	HandleOperationListStream		= 18,
	TokenStream				= 19,
	JavaScriptDataStream		= 20,

	ceStreamNull			= 0x8000,
	ceStreamSystemInfo			= 0x8001,
	ceStreamException			= 0x8002,
	ceStreamModuleList			= 0x8003,
	ceStreamProcessList			= 0x8004,
	ceStreamThreadList			= 0x8005,
	ceStreamThreadContextList		= 0x8006,
	ceStreamThreadCallStackList		= 0x8007,
	ceStreamMemoryVirtualList		= 0x8008,
	ceStreamMemoryPhysicalList		= 0x8009,
	ceStreamBucketParameters		= 0x800A,
	ceStreamProcessModuleMap		= 0x800B,
	ceStreamDiagnosisList		= 0x800C,

	LastReservedStream			= 0xffff

} MINIDUMP_STREAM_TYPE;

typedef struct _MINIDUMP_DIRECTORY {
	ULONG32 StreamType;
	MINIDUMP_LOCATION_DESCRIPTOR Location;
} MINIDUMP_DIRECTORY, *PMINIDUMP_DIRECTORY;


typedef struct _MINIDUMP_STRING {
	ULONG32 Length;
	WCHAR   Buffer [0];
} MINIDUMP_STRING, *PMINIDUMP_STRING;

typedef union _CPU_INFORMATION {

	struct {
		ULONG32 VendorId [ 3 ];
		ULONG32 VersionInformation;
		ULONG32 FeatureInformation;
		ULONG32 AMDExtendedCpuFeatures;
	} X86CpuInfo;
	struct {
		ULONG64 ProcessorFeatures [ 2 ];
	} OtherCpuInfo;
} CPU_INFORMATION, *PCPU_INFORMATION;

typedef struct _MINIDUMP_SYSTEM_INFO {
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;

	struct {
		UCHAR NumberOfProcessors;
		UCHAR ProductType;
	};

	ULONG32 MajorVersion;
	ULONG32 MinorVersion;
	ULONG32 BuildNumber;

	RVA CSDVersionRva;

	union {
		ULONG32 Reserved1;
		struct {
			USHORT SuiteMask;
			USHORT Reserved2;
		};
	};

	CPU_INFORMATION Cpu;

} MINIDUMP_SYSTEM_INFO, *PMINIDUMP_SYSTEM_INFO;

typedef struct _MINIDUMP_THREAD {
	ULONG32 ThreadId;
	ULONG32 SuspendCount;
	ULONG32 PriorityClass;
	ULONG32 Priority;
	ULONG64 Teb;
	MINIDUMP_MEMORY_DESCRIPTOR Stack;
	MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
} MINIDUMP_THREAD, *PMINIDUMP_THREAD;

typedef struct _MINIDUMP_THREAD_LIST {
	ULONG32 NumberOfThreads;
	MINIDUMP_THREAD Threads [0];
} MINIDUMP_THREAD_LIST, *PMINIDUMP_THREAD_LIST;


typedef struct _MINIDUMP_THREAD_EX {
	ULONG32 ThreadId;
	ULONG32 SuspendCount;
	ULONG32 PriorityClass;
	ULONG32 Priority;
	ULONG64 Teb;
	MINIDUMP_MEMORY_DESCRIPTOR Stack;
	MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
	MINIDUMP_MEMORY_DESCRIPTOR BackingStore;
} MINIDUMP_THREAD_EX, *PMINIDUMP_THREAD_EX;

typedef struct _MINIDUMP_THREAD_EX_LIST {
	ULONG32 NumberOfThreads;
	MINIDUMP_THREAD_EX Threads [0];
} MINIDUMP_THREAD_EX_LIST, *PMINIDUMP_THREAD_EX_LIST;


typedef struct _MINIDUMP_EXCEPTION  {
	ULONG32 ExceptionCode;
	ULONG32 ExceptionFlags;
	ULONG64 ExceptionRecord;
	ULONG64 ExceptionAddress;
	ULONG32 NumberParameters;
	ULONG32 __unusedAlignment;
	ULONG64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} MINIDUMP_EXCEPTION, *PMINIDUMP_EXCEPTION;


typedef struct MINIDUMP_EXCEPTION_STREAM {
	ULONG32 ThreadId;
	ULONG32  __alignment;
	MINIDUMP_EXCEPTION ExceptionRecord;
	MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
} MINIDUMP_EXCEPTION_STREAM, *PMINIDUMP_EXCEPTION_STREAM;


typedef struct _MINIDUMP_MODULE {
	ULONG64 BaseOfImage;
	ULONG32 SizeOfImage;
	ULONG32 CheckSum;
	ULONG32 TimeDateStamp;
	RVA ModuleNameRva;
	VS_FIXEDFILEINFO VersionInfo;
	MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
	MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
	ULONG64 Reserved0;
	ULONG64 Reserved1;
} MINIDUMP_MODULE, *PMINIDUMP_MODULE;

typedef struct _MINIDUMP_MODULE_LIST {
	ULONG32 NumberOfModules;
	MINIDUMP_MODULE Modules [ 0 ];
} MINIDUMP_MODULE_LIST, *PMINIDUMP_MODULE_LIST;


typedef struct _MINIDUMP_MEMORY_LIST {
	ULONG32 NumberOfMemoryRanges;
	MINIDUMP_MEMORY_DESCRIPTOR MemoryRanges [0];
} MINIDUMP_MEMORY_LIST, *PMINIDUMP_MEMORY_LIST;

typedef struct _MINIDUMP_MEMORY64_LIST {
	ULONG64 NumberOfMemoryRanges;
	RVA64 BaseRva;
	MINIDUMP_MEMORY_DESCRIPTOR64 MemoryRanges [0];
} MINIDUMP_MEMORY64_LIST, *PMINIDUMP_MEMORY64_LIST;

typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
	DWORD ThreadId;
	PEXCEPTION_POINTERS_i386 ExceptionPointers;
	BOOL ClientPointers;
} MINIDUMP_EXCEPTION_INFORMATION, *PMINIDUMP_EXCEPTION_INFORMATION;

typedef struct _MINIDUMP_EXCEPTION_INFORMATION64 {
	DWORD ThreadId;
	ULONG64 ExceptionRecord;
	ULONG64 ContextRecord;
	BOOL ClientPointers;
} MINIDUMP_EXCEPTION_INFORMATION64, *PMINIDUMP_EXCEPTION_INFORMATION64;


typedef enum _MINIDUMP_HANDLE_OBJECT_INFORMATION_TYPE {
	MiniHandleObjectInformationNone,
	MiniThreadInformation1,
	MiniMutantInformation1,
	MiniMutantInformation2,
	MiniProcessInformation1,
	MiniProcessInformation2,
	MiniEventInformation1,
	MiniSectionInformation1,
	MiniHandleObjectInformationTypeMax
} MINIDUMP_HANDLE_OBJECT_INFORMATION_TYPE;

typedef struct _MINIDUMP_HANDLE_OBJECT_INFORMATION {
	RVA NextInfoRva;
	ULONG32 InfoType;
	ULONG32 SizeOfInfo;
} MINIDUMP_HANDLE_OBJECT_INFORMATION;

typedef struct _MINIDUMP_HANDLE_DESCRIPTOR {
	ULONG64 Handle;
	RVA TypeNameRva;
	RVA ObjectNameRva;
	ULONG32 Attributes;
	ULONG32 GrantedAccess;
	ULONG32 HandleCount;
	ULONG32 PointerCount;
} MINIDUMP_HANDLE_DESCRIPTOR, *PMINIDUMP_HANDLE_DESCRIPTOR;

typedef struct _MINIDUMP_HANDLE_DESCRIPTOR_2 {
	ULONG64 Handle;
	RVA TypeNameRva;
	RVA ObjectNameRva;
	ULONG32 Attributes;
	ULONG32 GrantedAccess;
	ULONG32 HandleCount;
	ULONG32 PointerCount;
	RVA ObjectInfoRva;
	ULONG32 Reserved0;
} MINIDUMP_HANDLE_DESCRIPTOR_2, *PMINIDUMP_HANDLE_DESCRIPTOR_2;


typedef MINIDUMP_HANDLE_DESCRIPTOR_2 MINIDUMP_HANDLE_DESCRIPTOR_N;
typedef MINIDUMP_HANDLE_DESCRIPTOR_N *PMINIDUMP_HANDLE_DESCRIPTOR_N;

typedef struct _MINIDUMP_HANDLE_DATA_STREAM {
	ULONG32 SizeOfHeader;
	ULONG32 SizeOfDescriptor;
	ULONG32 NumberOfDescriptors;
	ULONG32 Reserved;
} MINIDUMP_HANDLE_DATA_STREAM, *PMINIDUMP_HANDLE_DATA_STREAM;

typedef struct _MINIDUMP_HANDLE_OPERATION_LIST {
	ULONG32 SizeOfHeader;
	ULONG32 SizeOfEntry;
	ULONG32 NumberOfEntries;
	ULONG32 Reserved;
} MINIDUMP_HANDLE_OPERATION_LIST, *PMINIDUMP_HANDLE_OPERATION_LIST;


typedef struct _MINIDUMP_FUNCTION_TABLE_DESCRIPTOR {
	ULONG64 MinimumAddress;
	ULONG64 MaximumAddress;
	ULONG64 BaseAddress;
	ULONG32 EntryCount;
	ULONG32 SizeOfAlignPad;
} MINIDUMP_FUNCTION_TABLE_DESCRIPTOR, *PMINIDUMP_FUNCTION_TABLE_DESCRIPTOR;

typedef struct _MINIDUMP_FUNCTION_TABLE_STREAM {
	ULONG32 SizeOfHeader;
	ULONG32 SizeOfDescriptor;
	ULONG32 SizeOfNativeDescriptor;
	ULONG32 SizeOfFunctionEntry;
	ULONG32 NumberOfDescriptors;
	ULONG32 SizeOfAlignPad;
} MINIDUMP_FUNCTION_TABLE_STREAM, *PMINIDUMP_FUNCTION_TABLE_STREAM;


typedef struct _MINIDUMP_UNLOADED_MODULE {
	ULONG64 BaseOfImage;
	ULONG32 SizeOfImage;
	ULONG32 CheckSum;
	ULONG32 TimeDateStamp;
	RVA ModuleNameRva;
} MINIDUMP_UNLOADED_MODULE, *PMINIDUMP_UNLOADED_MODULE;


typedef struct _MINIDUMP_UNLOADED_MODULE_LIST {
	ULONG32 SizeOfHeader;
	ULONG32 SizeOfEntry;
	ULONG32 NumberOfEntries;
} MINIDUMP_UNLOADED_MODULE_LIST, *PMINIDUMP_UNLOADED_MODULE_LIST;


#define MINIDUMP_MISC1_PROCESS_ID		0x00000001
#define MINIDUMP_MISC1_PROCESS_TIMES		0x00000002
#define MINIDUMP_MISC1_PROCESSOR_POWER_INFO	0x00000004
#define MINIDUMP_MISC3_PROCESS_INTEGRITY	0x00000010
#define MINIDUMP_MISC3_PROCESS_EXECUTE_FLAGS	0x00000020
#define MINIDUMP_MISC3_TIMEZONE			0x00000040
#define MINIDUMP_MISC3_PROTECTED_PROCESS	0x00000080
#define MINIDUMP_MISC4_BUILDSTRING		0x00000100

typedef struct _MINIDUMP_MISC_INFO {
	ULONG32 SizeOfInfo;
	ULONG32 Flags1;
	ULONG32 ProcessId;
	ULONG32 ProcessCreateTime;
	ULONG32 ProcessUserTime;
	ULONG32 ProcessKernelTime;
} MINIDUMP_MISC_INFO, *PMINIDUMP_MISC_INFO;

typedef struct _MINIDUMP_MISC_INFO_2 {
	ULONG32 SizeOfInfo;
	ULONG32 Flags1;
	ULONG32 ProcessId;
	ULONG32 ProcessCreateTime;
	ULONG32 ProcessUserTime;
	ULONG32 ProcessKernelTime;
	ULONG32 ProcessorMaxMhz;
	ULONG32 ProcessorCurrentMhz;
	ULONG32 ProcessorMhzLimit;
	ULONG32 ProcessorMaxIdleState;
	ULONG32 ProcessorCurrentIdleState;
} MINIDUMP_MISC_INFO_2, *PMINIDUMP_MISC_INFO_2;

typedef struct _MINIDUMP_MISC_INFO_3 {
	ULONG32 SizeOfInfo;
	ULONG32 Flags1;
	ULONG32 ProcessId;
	ULONG32 ProcessCreateTime;
	ULONG32 ProcessUserTime;
	ULONG32 ProcessKernelTime;
	ULONG32 ProcessorMaxMhz;
	ULONG32 ProcessorCurrentMhz;
	ULONG32 ProcessorMhzLimit;
	ULONG32 ProcessorMaxIdleState;
	ULONG32 ProcessorCurrentIdleState;
	ULONG32 ProcessIntegrityLevel;
	ULONG32 ProcessExecuteFlags;
	ULONG32 ProtectedProcess;
	ULONG32 TimeZoneId;
	TIME_ZONE_INFORMATION TimeZone;
} MINIDUMP_MISC_INFO_3, *PMINIDUMP_MISC_INFO_3;

typedef struct _MINIDUMP_MISC_INFO_4 {
	ULONG32 SizeOfInfo;
	ULONG32 Flags1;
	ULONG32 ProcessId;
	ULONG32 ProcessCreateTime;
	ULONG32 ProcessUserTime;
	ULONG32 ProcessKernelTime;
	ULONG32 ProcessorMaxMhz;
	ULONG32 ProcessorCurrentMhz;
	ULONG32 ProcessorMhzLimit;
	ULONG32 ProcessorMaxIdleState;
	ULONG32 ProcessorCurrentIdleState;
	ULONG32 ProcessIntegrityLevel;
	ULONG32 ProcessExecuteFlags;
	ULONG32 ProtectedProcess;
	ULONG32 TimeZoneId;
	TIME_ZONE_INFORMATION TimeZone;
	WCHAR   BuildString[WINDOWS_MAX_PATH];
	WCHAR   DbgBldStr[40];
} MINIDUMP_MISC_INFO_4, *PMINIDUMP_MISC_INFO_4;


typedef MINIDUMP_MISC_INFO_4 MINIDUMP_MISC_INFO_N;
typedef MINIDUMP_MISC_INFO_N *PMINIDUMP_MISC_INFO_N;

typedef struct _MINIDUMP_MEMORY_INFO {
	ULONG64 BaseAddress;
	ULONG64 AllocationBase;
	ULONG32 AllocationProtect;
	ULONG32 __alignment1;
	ULONG64 RegionSize;
	ULONG32 State;
	ULONG32 Protect;
	ULONG32 Type;
	ULONG32 __alignment2;
} MINIDUMP_MEMORY_INFO, *PMINIDUMP_MEMORY_INFO;

typedef struct _MINIDUMP_MEMORY_INFO_LIST {
	ULONG SizeOfHeader;
	ULONG SizeOfEntry;
	ULONG64 NumberOfEntries;
} MINIDUMP_MEMORY_INFO_LIST, *PMINIDUMP_MEMORY_INFO_LIST;


#define MINIDUMP_THREAD_INFO_ERROR_THREAD	0x00000001
#define MINIDUMP_THREAD_INFO_WRITING_THREAD	0x00000002
#define MINIDUMP_THREAD_INFO_EXITED_THREAD	0x00000004
#define MINIDUMP_THREAD_INFO_INVALID_INFO	0x00000008
#define MINIDUMP_THREAD_INFO_INVALID_CONTEXT	0x00000010
#define MINIDUMP_THREAD_INFO_INVALID_TEB	0x00000020

typedef struct _MINIDUMP_THREAD_INFO {
	ULONG32 ThreadId;
	ULONG32 DumpFlags;
	ULONG32 DumpError;
	ULONG32 ExitStatus;
	ULONG64 CreateTime;
	ULONG64 ExitTime;
	ULONG64 KernelTime;
	ULONG64 UserTime;
	ULONG64 StartAddress;
	ULONG64 Affinity;
} MINIDUMP_THREAD_INFO, *PMINIDUMP_THREAD_INFO;

typedef struct _MINIDUMP_THREAD_INFO_LIST {
	ULONG SizeOfHeader;
	ULONG SizeOfEntry;
	ULONG NumberOfEntries;
} MINIDUMP_THREAD_INFO_LIST, *PMINIDUMP_THREAD_INFO_LIST;


typedef struct _MINIDUMP_TOKEN_INFO_HEADER {
	ULONG   TokenSize;
	ULONG   TokenId;
	ULONG64 TokenHandle;
} MINIDUMP_TOKEN_INFO_HEADER, *PMINIDUMP_TOKEN_INFO_HEADER;

typedef struct _MINIDUMP_TOKEN_INFO_LIST {
	ULONG TokenListSize;
	ULONG TokenListEntries;
	ULONG ListHeaderSize;
	ULONG ElementHeaderSize;
} MINIDUMP_TOKEN_INFO_LIST, *PMINIDUMP_TOKEN_INFO_LIST;

typedef struct _MINIDUMP_USER_RECORD {
	ULONG32 Type;
	MINIDUMP_LOCATION_DESCRIPTOR Memory;
} MINIDUMP_USER_RECORD, *PMINIDUMP_USER_RECORD;


typedef struct _MINIDUMP_USER_STREAM {
	ULONG32 Type;
	ULONG BufferSize;
	PVOID Buffer;
} MINIDUMP_USER_STREAM, *PMINIDUMP_USER_STREAM;


typedef struct _MINIDUMP_USER_STREAM_INFORMATION {
	ULONG UserStreamCount;
	PMINIDUMP_USER_STREAM UserStreamArray;
} MINIDUMP_USER_STREAM_INFORMATION, *PMINIDUMP_USER_STREAM_INFORMATION;

typedef enum _MINIDUMP_CALLBACK_TYPE {
	ModuleCallback,
	ThreadCallback,
	ThreadExCallback,
	IncludeThreadCallback,
	IncludeModuleCallback,
	MemoryCallback,
	CancelCallback,
	WriteKernelMinidumpCallback,
	KernelMinidumpStatusCallback,
	RemoveMemoryCallback,
	IncludeVmRegionCallback,
	IoStartCallback,
	IoWriteAllCallback,
	IoFinishCallback,
	ReadMemoryFailureCallback,
	SecondaryFlagsCallback,
	IsProcessSnapshotCallback,
	VmStartCallback,
	VmQueryCallback,
	VmPreReadCallback,
	VmPostReadCallback,
} MINIDUMP_CALLBACK_TYPE;

typedef struct _MINIDUMP_INCLUDE_THREAD_CALLBACK {
	ULONG ThreadId;
} MINIDUMP_INCLUDE_THREAD_CALLBACK, *PMINIDUMP_INCLUDE_THREAD_CALLBACK;


typedef enum _THREAD_WRITE_FLAGS {
	ThreadWriteThread		= 0x0001,
	ThreadWriteStack		= 0x0002,
	ThreadWriteContext		= 0x0004,
	ThreadWriteBackingStore		= 0x0008,
	ThreadWriteInstructionWindow	= 0x0010,
	ThreadWriteThreadData		= 0x0020,
	ThreadWriteThreadInfo		= 0x0040
} THREAD_WRITE_FLAGS;

typedef struct _MINIDUMP_MODULE_CALLBACK {
	PWCHAR FullPath;
	ULONG64 BaseOfImage;
	ULONG SizeOfImage;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	VS_FIXEDFILEINFO VersionInfo;
	PVOID CvRecord;
	ULONG SizeOfCvRecord;
	PVOID MiscRecord;
	ULONG SizeOfMiscRecord;
} MINIDUMP_MODULE_CALLBACK, *PMINIDUMP_MODULE_CALLBACK;


typedef struct _MINIDUMP_INCLUDE_MODULE_CALLBACK {
	ULONG64 BaseOfImage;
} MINIDUMP_INCLUDE_MODULE_CALLBACK, *PMINIDUMP_INCLUDE_MODULE_CALLBACK;


typedef enum _MODULE_WRITE_FLAGS {
	ModuleWriteModule		= 0x0001,
	ModuleWriteDataSeg		= 0x0002,
	ModuleWriteMiscRecord		= 0x0004,
	ModuleWriteCvRecord		= 0x0008,
	ModuleReferencedByMemory	= 0x0010,
	ModuleWriteTlsData		= 0x0020,
	ModuleWriteCodeSegs		= 0x0040
} MODULE_WRITE_FLAGS;


typedef struct _MINIDUMP_IO_CALLBACK {
	HANDLE Handle;
	ULONG64 Offset;
	PVOID Buffer;
	ULONG BufferBytes;
} MINIDUMP_IO_CALLBACK, *PMINIDUMP_IO_CALLBACK;


typedef struct _MINIDUMP_READ_MEMORY_FAILURE_CALLBACK {
	ULONG64 Offset;
	ULONG Bytes;
	HRESULT FailureStatus;
} MINIDUMP_READ_MEMORY_FAILURE_CALLBACK,
*PMINIDUMP_READ_MEMORY_FAILURE_CALLBACK;

typedef struct _MINIDUMP_VM_QUERY_CALLBACK {
	ULONG64 Offset;
} MINIDUMP_VM_QUERY_CALLBACK, *PMINIDUMP_VM_QUERY_CALLBACK;

typedef struct _MINIDUMP_VM_PRE_READ_CALLBACK {
	ULONG64 Offset;
	PVOID Buffer;
	ULONG Size;
} MINIDUMP_VM_PRE_READ_CALLBACK, *PMINIDUMP_VM_PRE_READ_CALLBACK;

typedef struct _MINIDUMP_VM_POST_READ_CALLBACK {
	ULONG64 Offset;
	PVOID Buffer;
	ULONG Size;
	ULONG Completed;
	HRESULT Status;
} MINIDUMP_VM_POST_READ_CALLBACK, *PMINIDUMP_VM_POST_READ_CALLBACK;

typedef struct _MINIDUMP_CALLBACK_OUTPUT {
	union {
		ULONG ModuleWriteFlags;
		ULONG ThreadWriteFlags;
		ULONG SecondaryFlags;
		struct {
			ULONG64 MemoryBase;
			ULONG MemorySize;
		};
		struct {
			BOOL CheckCancel;
			BOOL Cancel;
		};
		HANDLE Handle;
		struct {
			MINIDUMP_MEMORY_INFO VmRegion;
			BOOL Continue;
		};
		struct {
			HRESULT VmQueryStatus;
			MINIDUMP_MEMORY_INFO VmQueryResult;
		};
		struct {
			HRESULT VmReadStatus;
			ULONG VmReadBytesCompleted;
		};
		HRESULT Status;
	};
} MINIDUMP_CALLBACK_OUTPUT, *PMINIDUMP_CALLBACK_OUTPUT;


typedef enum _MINIDUMP_TYPE {
	MiniDumpNormal				= 0x00000000,
	MiniDumpWithDataSegs			= 0x00000001,
	MiniDumpWithFullMemory			= 0x00000002,
	MiniDumpWithHandleData			= 0x00000004,
	MiniDumpFilterMemory			= 0x00000008,
	MiniDumpScanMemory			= 0x00000010,
	MiniDumpWithUnloadedModules		= 0x00000020,
	MiniDumpWithIndirectlyReferencedMemory	= 0x00000040,
	MiniDumpFilterModulePaths		= 0x00000080,
	MiniDumpWithProcessThreadData		= 0x00000100,
	MiniDumpWithPrivateReadWriteMemory	= 0x00000200,
	MiniDumpWithoutOptionalData		= 0x00000400,
	MiniDumpWithFullMemoryInfo		= 0x00000800,
	MiniDumpWithThreadInfo			= 0x00001000,
	MiniDumpWithCodeSegs			= 0x00002000,
	MiniDumpWithoutAuxiliaryState		= 0x00004000,
	MiniDumpWithFullAuxiliaryState		= 0x00008000,
	MiniDumpWithPrivateWriteCopyMemory	= 0x00010000,
	MiniDumpIgnoreInaccessibleMemory	= 0x00020000,
	MiniDumpWithTokenInformation		= 0x00040000,
	MiniDumpWithModuleHeaders		= 0x00080000,
	MiniDumpFilterTriage			= 0x00100000,
	MiniDumpValidTypeFlags			= 0x001fffff
} MINIDUMP_TYPE;


typedef enum _MINIDUMP_SECONDARY_FLAGS {
	MiniSecondaryWithoutPowerInfo	= 0x00000001,
	MiniSecondaryValidFlags		= 0x00000001
} MINIDUMP_SECONDARY_FLAGS;



#define ARCH i386
#include "platform.h"
#undef ARCH

#define ARCH ARM
#include "platform.h"
#undef ARCH

#define ARCH IA64
#include "platform.h"
#undef ARCH

#define ARCH AMD64
#include "platform.h"
#undef ARCH



#endif /* MDMP_SPECS_H */
