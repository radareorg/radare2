#ifndef MDMP_SPECS_H
#define MDMP_SPECS_H

#define MDMP_PLATFORM_PURE(NAME, ARCH) NAME ## _ ## ARCH
#define MDMP_PLATFORM(NAME, ARCH) MDMP_PLATFORM_PURE(NAME, ARCH)

#define MINIDUMP_SIGNATURE 0x504d444d /* PMDM */
#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define WINDOWS_MAX_PATH 260

#define R2_HRESULT long

typedef ut32 RVA;
typedef ut64 RVA64;


#define WINDOWS_PROCESSOR_ARCHITECTURE_INTEL            0x0000
#define WINDOWS_PROCESSOR_ARCHITECTURE_MIPS             0x0001
#define WINDOWS_PROCESSOR_ARCHITECTURE_ALPHA            0x0002
#define WINDOWS_PROCESSOR_ARCHITECTURE_PPC              0x0003
#define WINDOWS_PROCESSOR_ARCHITECTURE_SHX              0x0004
#define WINDOWS_PROCESSOR_ARCHITECTURE_ARM              0x0005
#define WINDOWS_PROCESSOR_ARCHITECTURE_IA64             0x0006
#define WINDOWS_PROCESSOR_ARCHITECTURE_ALPHA64          0x0007
#define WINDOWS_PROCESSOR_ARCHITECTURE_MSIL             0x0008
#define WINDOWS_PROCESSOR_ARCHITECTURE_AMD64            0x0009
#define WINDOWS_PROCESSOR_ARCHITECTURE_IA32_ON_WIN64    0x000A
#define WINDOWS_PROCESSOR_ARCHITECTURE_NEUTRAL          0x000B
#define WINDOWS_PROCESSOR_ARCHITECTURE_UNKNOWN          0xFFFF

#define WINDOWS_VER_NT_WORKSTATION              0x0000001
#define WINDOWS_VER_NT_DOMAIN_CONTROLLER        0x0000002
#define WINDOWS_VER_NT_SERVER                   0x0000003

// XXX already in pe.h
typedef struct {
	ut32 dwSignature;
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
} WINDOWS_VS_FIXEDFILEINFO;

typedef struct _MINIDUMP_HEADER {
	ut32 Signature;
	ut32 Version;
	ut32 NumberOfStreams;
	RVA StreamDirectoryRva;
	ut32 CheckSum;
	ut32 TimeDateStamp;
	ut64 Flags;
} MINIDUMP_HEADER, *PMINIDUMP_HEADER;

typedef struct _MINIDUMP_LOCATION_DESCRIPTOR {
	ut32 DataSize;
	RVA Rva;
} MINIDUMP_LOCATION_DESCRIPTOR;

typedef struct _MINIDUMP_LOCATION_DESCRIPTOR64 {
	ut64 DataSize;
	RVA64 Rva;
} MINIDUMP_LOCATION_DESCRIPTOR64;

typedef struct _MINIDUMP_MEMORY_DESCRIPTOR {
	ut64 StartOfMemoryRange;
	MINIDUMP_LOCATION_DESCRIPTOR Memory;
} MINIDUMP_MEMORY_DESCRIPTOR, *PMINIDUMP_MEMORY_DESCRIPTOR;

typedef struct _MINIDUMP_MEMORY_DESCRIPTOR64 {
	ut64 StartOfMemoryRange;
	ut64 DataSize;
} MINIDUMP_MEMORY_DESCRIPTOR64, *PMINIDUMP_MEMORY_DESCRIPTOR64;

typedef enum _MINIDUMP_STREAM_TYPE {
	UnusedStream			= 0,
	ReservedStream0			= 1,
	ReservedStream1			= 2,
	ThreadListStream		= 3,
	ModuleListStream		= 4,
	MemoryListStream		= 5,
	ExceptionStream			= 6,
	SystemInfoStream		= 7,
	ThreadExListStream		= 8,
	Memory64ListStream		= 9,
	CommentStreamA			= 10,
	CommentStreamW			= 11,
	HandleDataStream		= 12,
	FunctionTableStream		= 13,
	UnloadedModuleListStream	= 14,
	MiscInfoStream			= 15,
	MemoryInfoListStream		= 16,
	ThreadInfoListStream		= 17,
	HandleOperationListStream	= 18,
	TokenStream			= 19,
	JavaScriptDataStream		= 20,
	ceStreamNull			= 0x8000,
	ceStreamSystemInfo		= 0x8001,
	ceStreamException		= 0x8002,
	ceStreamModuleList		= 0x8003,
	ceStreamProcessList		= 0x8004,
	ceStreamThreadList		= 0x8005,
	ceStreamThreadContextList	= 0x8006,
	ceStreamThreadCallStackList	= 0x8007,
	ceStreamMemoryVirtualList	= 0x8008,
	ceStreamMemoryPhysicalList	= 0x8009,
	ceStreamBucketParameters	= 0x800A,
	ceStreamProcessModuleMap	= 0x800B,
	ceStreamDiagnosisList		= 0x800C,
	LastReservedStream		= 0xffff
} MINIDUMP_STREAM_TYPE;

typedef struct _MINIDUMP_DIRECTORY {
	ut32 StreamType;
	MINIDUMP_LOCATION_DESCRIPTOR Location;
} MINIDUMP_DIRECTORY, *PMINIDUMP_DIRECTORY;

typedef struct _MINIDUMP_STRING {
	ut32 Length;
	ut16 Buffer[0];
} MINIDUMP_STRING, *PMINIDUMP_STRING;

typedef union _CPU_INFORMATION {
	struct {
		ut32 VendorId [ 3 ];
		ut32 VersionInformation;
		ut32 FeatureInformation;
		ut32 AMDExtendedCpuFeatures;
	} X86CpuInfo;
	struct {
		ut64 ProcessorFeatures [ 2 ];
	} OtherCpuInfo;
} CPU_INFORMATION, *PCPU_INFORMATION;

typedef struct _MINIDUMP_SYSTEM_INFO {
	ut16 ProcessorArchitecture;
	ut16 ProcessorLevel;
	ut16 ProcessorRevision;

	struct {
		ut8 NumberOfProcessors;
		ut8 ProductType;
	};

	ut32 MajorVersion;
	ut32 MinorVersion;
	ut32 BuildNumber;

	RVA CSDVersionRva;

	union {
		ut32 Reserved1;
		struct {
			ut16 SuiteMask;
			ut16 Reserved2;
		};
	};

	CPU_INFORMATION Cpu;
} MINIDUMP_SYSTEM_INFO, *PMINIDUMP_SYSTEM_INFO;

typedef struct _MINIDUMP_THREAD {
	ut32 ThreadId;
	ut32 SuspendCount;
	ut32 PriorityClass;
	ut32 Priority;
	ut64 Teb;
	MINIDUMP_MEMORY_DESCRIPTOR Stack;
	MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
} MINIDUMP_THREAD, *PMINIDUMP_THREAD;

typedef struct _MINIDUMP_THREAD_LIST {
	ut32 NumberOfThreads;
	MINIDUMP_THREAD Threads [0];
} MINIDUMP_THREAD_LIST, *PMINIDUMP_THREAD_LIST;


typedef struct _MINIDUMP_THREAD_EX {
	ut32 ThreadId;
	ut32 SuspendCount;
	ut32 PriorityClass;
	ut32 Priority;
	ut64 Teb;
	MINIDUMP_MEMORY_DESCRIPTOR Stack;
	MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
	MINIDUMP_MEMORY_DESCRIPTOR BackingStore;
} MINIDUMP_THREAD_EX, *PMINIDUMP_THREAD_EX;

typedef struct _MINIDUMP_THREAD_EX_LIST {
	ut32 NumberOfThreads;
	MINIDUMP_THREAD_EX Threads [0];
} MINIDUMP_THREAD_EX_LIST, *PMINIDUMP_THREAD_EX_LIST;


typedef struct _MINIDUMP_EXCEPTION  {
	ut32 ExceptionCode;
	ut32 ExceptionFlags;
	ut64 ExceptionRecord;
	ut64 ExceptionAddress;
	ut32 NumberParameters;
	ut32 __unusedAlignment;
	ut64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} MINIDUMP_EXCEPTION, *PMINIDUMP_EXCEPTION;


typedef struct MINIDUMP_EXCEPTION_STREAM {
	ut32 ThreadId;
	ut32  __alignment;
	MINIDUMP_EXCEPTION ExceptionRecord;
	MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
} MINIDUMP_EXCEPTION_STREAM, *PMINIDUMP_EXCEPTION_STREAM;


typedef struct _MINIDUMP_MODULE {
	ut64 BaseOfImage;
	ut32 SizeOfImage;
	ut32 CheckSum;
	ut32 TimeDateStamp;
	RVA ModuleNameRva;
	WINDOWS_VS_FIXEDFILEINFO VersionInfo;
	MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
	MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
	ut64 Reserved0;
	ut64 Reserved1;
} MINIDUMP_MODULE, *PMINIDUMP_MODULE;

typedef struct _MINIDUMP_MODULE_LIST {
	ut32 NumberOfModules;
	MINIDUMP_MODULE Modules [ 0 ];
} MINIDUMP_MODULE_LIST, *PMINIDUMP_MODULE_LIST;


typedef struct _MINIDUMP_MEMORY_LIST {
	ut32 NumberOfMemoryRanges;
	MINIDUMP_MEMORY_DESCRIPTOR MemoryRanges [0];
} MINIDUMP_MEMORY_LIST, *PMINIDUMP_MEMORY_LIST;

typedef struct _MINIDUMP_MEMORY64_LIST {
	ut64 NumberOfMemoryRanges;
	RVA64 BaseRva;
	MINIDUMP_MEMORY_DESCRIPTOR64 MemoryRanges [0];
} MINIDUMP_MEMORY64_LIST, *PMINIDUMP_MEMORY64_LIST;

typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
	ut32 ThreadId;
	PEXCEPTION_POINTERS_I386 ExceptionPointers;
	ut32/*bool*/ ClientPointers;
} MINIDUMP_EXCEPTION_INFORMATION, *PMINIDUMP_EXCEPTION_INFORMATION;

typedef struct _MINIDUMP_EXCEPTION_INFORMATION64 {
	ut32 ThreadId;
	ut64 ExceptionRecord;
	ut64 ContextRecord;
	ut32/*bool*/ ClientPointers;
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
	ut32 InfoType;
	ut32 SizeOfInfo;
} MINIDUMP_HANDLE_OBJECT_INFORMATION;

typedef struct _MINIDUMP_HANDLE_DESCRIPTOR {
	ut64 Handle;
	RVA TypeNameRva;
	RVA ObjectNameRva;
	ut32 Attributes;
	ut32 GrantedAccess;
	ut32 HandleCount;
	ut32 PointerCount;
} MINIDUMP_HANDLE_DESCRIPTOR, *PMINIDUMP_HANDLE_DESCRIPTOR;

typedef struct _MINIDUMP_HANDLE_DESCRIPTOR_2 {
	ut64 Handle;
	RVA TypeNameRva;
	RVA ObjectNameRva;
	ut32 Attributes;
	ut32 GrantedAccess;
	ut32 HandleCount;
	ut32 PointerCount;
	RVA ObjectInfoRva;
	ut32 Reserved0;
} MINIDUMP_HANDLE_DESCRIPTOR_2, *PMINIDUMP_HANDLE_DESCRIPTOR_2;


typedef MINIDUMP_HANDLE_DESCRIPTOR_2 MINIDUMP_HANDLE_DESCRIPTOR_N;
typedef MINIDUMP_HANDLE_DESCRIPTOR_N *PMINIDUMP_HANDLE_DESCRIPTOR_N;

typedef struct _MINIDUMP_HANDLE_DATA_STREAM {
	ut32 SizeOfHeader;
	ut32 SizeOfDescriptor;
	ut32 NumberOfDescriptors;
	ut32 Reserved;
} MINIDUMP_HANDLE_DATA_STREAM, *PMINIDUMP_HANDLE_DATA_STREAM;

typedef struct _MINIDUMP_HANDLE_OPERATION_LIST {
	ut32 SizeOfHeader;
	ut32 SizeOfEntry;
	ut32 NumberOfEntries;
	ut32 Reserved;
} MINIDUMP_HANDLE_OPERATION_LIST, *PMINIDUMP_HANDLE_OPERATION_LIST;


typedef struct _MINIDUMP_FUNCTION_TABLE_DESCRIPTOR {
	ut64 MinimumAddress;
	ut64 MaximumAddress;
	ut64 BaseAddress;
	ut32 EntryCount;
	ut32 SizeOfAlignPad;
} MINIDUMP_FUNCTION_TABLE_DESCRIPTOR, *PMINIDUMP_FUNCTION_TABLE_DESCRIPTOR;

typedef struct _MINIDUMP_FUNCTION_TABLE_STREAM {
	ut32 SizeOfHeader;
	ut32 SizeOfDescriptor;
	ut32 SizeOfNativeDescriptor;
	ut32 SizeOfFunctionEntry;
	ut32 NumberOfDescriptors;
	ut32 SizeOfAlignPad;
} MINIDUMP_FUNCTION_TABLE_STREAM, *PMINIDUMP_FUNCTION_TABLE_STREAM;


typedef struct _MINIDUMP_UNLOADED_MODULE {
	ut64 BaseOfImage;
	ut32 SizeOfImage;
	ut32 CheckSum;
	ut32 TimeDateStamp;
	RVA ModuleNameRva;
} MINIDUMP_UNLOADED_MODULE, *PMINIDUMP_UNLOADED_MODULE;


typedef struct _MINIDUMP_UNLOADED_MODULE_LIST {
	ut32 SizeOfHeader;
	ut32 SizeOfEntry;
	ut32 NumberOfEntries;
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
	ut32 SizeOfInfo;
	ut32 Flags1;
	ut32 ProcessId;
	ut32 ProcessCreateTime;
	ut32 ProcessUserTime;
	ut32 ProcessKernelTime;
} MINIDUMP_MISC_INFO, *PMINIDUMP_MISC_INFO;

typedef struct _MINIDUMP_MISC_INFO_2 {
	ut32 SizeOfInfo;
	ut32 Flags1;
	ut32 ProcessId;
	ut32 ProcessCreateTime;
	ut32 ProcessUserTime;
	ut32 ProcessKernelTime;
	ut32 ProcessorMaxMhz;
	ut32 ProcessorCurrentMhz;
	ut32 ProcessorMhzLimit;
	ut32 ProcessorMaxIdleState;
	ut32 ProcessorCurrentIdleState;
} MINIDUMP_MISC_INFO_2, *PMINIDUMP_MISC_INFO_2;

typedef struct _MINIDUMP_MISC_INFO_3 {
	ut32 SizeOfInfo;
	ut32 Flags1;
	ut32 ProcessId;
	ut32 ProcessCreateTime;
	ut32 ProcessUserTime;
	ut32 ProcessKernelTime;
	ut32 ProcessorMaxMhz;
	ut32 ProcessorCurrentMhz;
	ut32 ProcessorMhzLimit;
	ut32 ProcessorMaxIdleState;
	ut32 ProcessorCurrentIdleState;
	ut32 ProcessIntegrityLevel;
	ut32 ProcessExecuteFlags;
	ut32 ProtectedProcess;
	ut32 TimeZoneId;
	WINDOWS_TIME_ZONE_INFORMATION TimeZone;
} MINIDUMP_MISC_INFO_3, *PMINIDUMP_MISC_INFO_3;

typedef struct _MINIDUMP_MISC_INFO_4 {
	ut32 SizeOfInfo;
	ut32 Flags1;
	ut32 ProcessId;
	ut32 ProcessCreateTime;
	ut32 ProcessUserTime;
	ut32 ProcessKernelTime;
	ut32 ProcessorMaxMhz;
	ut32 ProcessorCurrentMhz;
	ut32 ProcessorMhzLimit;
	ut32 ProcessorMaxIdleState;
	ut32 ProcessorCurrentIdleState;
	ut32 ProcessIntegrityLevel;
	ut32 ProcessExecuteFlags;
	ut32 ProtectedProcess;
	ut32 TimeZoneId;
	WINDOWS_TIME_ZONE_INFORMATION TimeZone;
	ut16 BuildString[WINDOWS_MAX_PATH];
	ut16 DbgBldStr[40];
} MINIDUMP_MISC_INFO_4, *PMINIDUMP_MISC_INFO_4;


typedef MINIDUMP_MISC_INFO_4 MINIDUMP_MISC_INFO_N;
typedef MINIDUMP_MISC_INFO_N *PMINIDUMP_MISC_INFO_N;

typedef struct _MINIDUMP_MEMORY_INFO {
	ut64 BaseAddress;
	ut64 AllocationBase;
	ut32 AllocationProtect;
	ut32 __alignment1;
	ut64 RegionSize;
	ut32 State;
	ut32 Protect;
	ut32 Type;
	ut32 __alignment2;
} MINIDUMP_MEMORY_INFO, *PMINIDUMP_MEMORY_INFO;

typedef struct _MINIDUMP_MEMORY_INFO_LIST {
	ut32 SizeOfHeader;
	ut32 SizeOfEntry;
	ut64 NumberOfEntries;
} MINIDUMP_MEMORY_INFO_LIST, *PMINIDUMP_MEMORY_INFO_LIST;


#define MINIDUMP_THREAD_INFO_ERROR_THREAD	0x00000001
#define MINIDUMP_THREAD_INFO_WRITING_THREAD	0x00000002
#define MINIDUMP_THREAD_INFO_EXITED_THREAD	0x00000004
#define MINIDUMP_THREAD_INFO_INVALID_INFO	0x00000008
#define MINIDUMP_THREAD_INFO_INVALID_CONTEXT	0x00000010
#define MINIDUMP_THREAD_INFO_INVALID_TEB	0x00000020

typedef struct _MINIDUMP_THREAD_INFO {
	ut32 ThreadId;
	ut32 DumpFlags;
	ut32 DumpError;
	ut32 ExitStatus;
	ut64 CreateTime;
	ut64 ExitTime;
	ut64 KernelTime;
	ut64 UserTime;
	ut64 StartAddress;
	ut64 Affinity;
} MINIDUMP_THREAD_INFO, *PMINIDUMP_THREAD_INFO;

typedef struct _MINIDUMP_THREAD_INFO_LIST {
	ut32 SizeOfHeader;
	ut32 SizeOfEntry;
	ut32 NumberOfEntries;
} MINIDUMP_THREAD_INFO_LIST, *PMINIDUMP_THREAD_INFO_LIST;


typedef struct _MINIDUMP_TOKEN_INFO_HEADER {
	ut32   TokenSize;
	ut32   TokenId;
	ut64 TokenHandle;
} MINIDUMP_TOKEN_INFO_HEADER, *PMINIDUMP_TOKEN_INFO_HEADER;

typedef struct _MINIDUMP_TOKEN_INFO_LIST {
	ut32 TokenListSize;
	ut32 TokenListEntries;
	ut32 ListHeaderSize;
	ut32 ElementHeaderSize;
} MINIDUMP_TOKEN_INFO_LIST, *PMINIDUMP_TOKEN_INFO_LIST;

typedef struct _MINIDUMP_USER_RECORD {
	ut32 Type;
	MINIDUMP_LOCATION_DESCRIPTOR Memory;
} MINIDUMP_USER_RECORD, *PMINIDUMP_USER_RECORD;


typedef struct _MINIDUMP_USER_STREAM {
	ut32 Type;
	ut32 BufferSize;
	void*Buffer;
} MINIDUMP_USER_STREAM, *PMINIDUMP_USER_STREAM;


typedef struct _MINIDUMP_USER_STREAM_INFORMATION {
	ut32 UserStreamCount;
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
	ut32 ThreadId;
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
	ut16 *FullPath;
	ut64 BaseOfImage;
	ut32 SizeOfImage;
	ut32 CheckSum;
	ut32 TimeDateStamp;
	WINDOWS_VS_FIXEDFILEINFO VersionInfo;
	void *CvRecord;
	ut32 SizeOfCvRecord;
	void *MiscRecord;
	ut32 SizeOfMiscRecord;
} MINIDUMP_MODULE_CALLBACK, *PMINIDUMP_MODULE_CALLBACK;


typedef struct _MINIDUMP_INCLUDE_MODULE_CALLBACK {
	ut64 BaseOfImage;
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
	void* Handle;
	ut64 Offset;
	void *Buffer;
	ut32 BufferBytes;
} MINIDUMP_IO_CALLBACK, *PMINIDUMP_IO_CALLBACK;


typedef struct _MINIDUMP_READ_MEMORY_FAILURE_CALLBACK {
	ut64 Offset;
	ut32 Bytes;
	R2_HRESULT FailureStatus;
} MINIDUMP_READ_MEMORY_FAILURE_CALLBACK,
*PMINIDUMP_READ_MEMORY_FAILURE_CALLBACK;

typedef struct _MINIDUMP_VM_QUERY_CALLBACK {
	ut64 Offset;
} MINIDUMP_VM_QUERY_CALLBACK, *PMINIDUMP_VM_QUERY_CALLBACK;

typedef struct _MINIDUMP_VM_PRE_READ_CALLBACK {
	ut64 Offset;
	void *Buffer;
	ut32 Size;
} MINIDUMP_VM_PRE_READ_CALLBACK, *PMINIDUMP_VM_PRE_READ_CALLBACK;

typedef struct _MINIDUMP_VM_POST_READ_CALLBACK {
	ut64 Offset;
	void *Buffer;
	ut32 Size;
	ut32 Completed;
	R2_HRESULT Status;
} MINIDUMP_VM_POST_READ_CALLBACK, *PMINIDUMP_VM_POST_READ_CALLBACK;

typedef struct _MINIDUMP_CALLBACK_OUTPUT {
	union {
		ut32 ModuleWriteFlags;
		ut32 ThreadWriteFlags;
		ut32 SecondaryFlags;
		struct {
			ut64 MemoryBase;
			ut32 MemorySize;
		};
		struct {
			ut32/*bool*/ CheckCancel;
			ut32/*bool*/ Cancel;
		};
		void *Handle;
		struct {
			MINIDUMP_MEMORY_INFO VmRegion;
			ut32/*bool*/ Continue;
		};
		struct {
			R2_HRESULT VmQueryStatus;
			MINIDUMP_MEMORY_INFO VmQueryResult;
		};
		struct {
			R2_HRESULT VmReadStatus;
			ut32 VmReadBytesCompleted;
		};
		R2_HRESULT Status;
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

#define ARCH I386
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
