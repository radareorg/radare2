#ifndef WINDOWS_HEAP_H
#define WINDOWS_HEAP_H

#include <windows.h>
#include <winternl.h>

/* 
	Defines most of heap related structures on Windows (some still missing)
	Tested only on Windows 10 1809 x64
	TODO:
		Clean/organize this: Order and Style
		-Can this be useful in unix? does mdmp even have a heap? remote dbg session?
		x86 vs x64 Struct Differences:
			-Structs definetly unaligned, check pdb
			-Do something like the the linux_heap that includes itself but with another bitness
				-Define macros to prefix structs to W32 or W64

		Some structs are different based on the Windows version (XP, Vista, 7, Server, 8, 8.1, 10)
		  and updates (Service Packs, Windows 10 Seasonal Updates)
			-Maybe use offsets instead of depending on structs
			-Create structs for each windows version (ie post-fix XP_SP2, 7, 10_1703)? (Oh god)
			-What about the parsing functions? Alter its behaviour depending on version or create
				one function for each version
*/
#define EXTRA_FLAG			(1ULL << (sizeof (size_t) * 8 - 1))

#define SHIFT 16
#define LFH_BLOCK			(1 << (SHIFT))
#define LARGE_BLOCK			(1 << (SHIFT + 1))
#define NT_BLOCK			(1 << (SHIFT + 2))
#define SEGMENT_HEAP_BLOCK	(1 << (SHIFT + 3))
#define VS_BLOCK			(1 << (SHIFT + 4))
#define BACKEND_BLOCK		(1 << (SHIFT + 5))

typedef struct _HEAP_LOCAL_DATA *PHEAP_LOCAL_DATA;
typedef struct _HEAP_SUBSEGMENT *PHEAP_SUBSEGMENT;
typedef struct _LFH_HEAP *PLFH_HEAP;
typedef struct _HEAP *PHEAP;

typedef struct _RTL_BALANCED_NODE *PRTL_BALANCED_NODE;
typedef struct _RTL_BALANCED_NODE {
	union {
		PRTL_BALANCED_NODE Children[2];
		struct {
			PRTL_BALANCED_NODE Left;
			PRTL_BALANCED_NODE Right;
		};
	};
	union {
		BYTE Red : 1;
		BYTE Balance : 2;
		WPARAM ParentValue;
	};
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE {
	PRTL_BALANCED_NODE Root;
	union {
		BOOL Encoded : 1;
		PRTL_BALANCED_NODE Min;
	};
} RTL_RB_TREE, *PRTL_RB_TREE;

typedef struct _HEAP_COUNTERS {
	WPARAM TotalMemoryReserved;
	WPARAM TotalMemoryCommitted;
	WPARAM TotalMemoryLargeUCR;
	WPARAM TotalSizeInVirtualBlocks;
	ULONG32 TotalSegments;
	ULONG32 TotalUCRs;
	ULONG32 CommittOps;
	ULONG32 DeCommitOps;
	ULONG32 LockAcquires;
	ULONG32 LockCollisions;
	ULONG32 CommitRate;
	ULONG32 DecommittRate;
	ULONG32 CommitFailures;
	ULONG32 InBlockCommitFailures;
	ULONG32 PollIntervalCounter;
	ULONG32 DecommitsSinceLastCheck;
	ULONG32 HeapPollInterval;
	ULONG32 AllocAndFreeOps;
	ULONG32 AllocationIndicesActive;
	ULONG32 InBlockDeccommits;
	WPARAM InBlockDeccomitSize;
	WPARAM HighWatermarkSize;
	WPARAM LastPolledSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS;

typedef struct _HEAP_BUCKET_COUNTERS {
	union {
		struct {
			ULONG TotalBlocks;
			ULONG SubSegmentCounts;
		};
		UINT64 Aggregate64;
	};
} HEAP_BUCKET_COUNTERS, *PHEAP_BUCKET_COUNTERS;

typedef struct _INTERLOCK_SEQ { // Is this right? NO!
	union {
		WORD Depth;
		union {
			union {
				WORD Hint : 15;
				WORD Lock : 1;
			};
			WORD Hint16;
		};
		INT32 Exchg;
	};
} INTERLOCK_SEQ, *PINTERLOCK_SEQ;

typedef struct _HEAP_UNPACKED_ENTRY {
#if defined(_M_X64)
	PVOID                       PreviousBlockPrivateData;
#endif
	union {
		struct {
			UINT16 Size;
			UINT8 Flags;
			UINT8 SmallTagIndex;
		};
#if defined(_M_X64)
		struct {
			ULONG32 SubSegmentCode;
			UINT16 PreviousSize;
			union {
				UINT8 SegmentOffset;
				UINT8 LFHFlags;
			};
			UINT8 UnusedBytes;
		};
		UINT64 CompactHeader;
#else
		ULONG32 SubSegmentCode;
#endif
	};
#if !defined(_M_X64)
	UINT16 PreviousSize;
	union {
		UINT8 SegmentOffset;
		UINT8 LFHFlags;
	};
	UINT8 UnusedBytes;
#endif
} HEAP_UNPACKED_ENTRY, *PHEAP_UNPACKED_ENTRY;

typedef struct _HEAP_EXTENDED_ENTRY {
#if defined(_M_X64)
	PVOID Reserved;
#endif
	union {
		struct {
			UINT16 FunctionIndex;
			UINT16 ContextValue;
		};
		ULONG32 InterceptorValue;
	};
	UINT16 UnusedBytesLength;
	UINT8 EntryOffset;
	UINT8 ExtendedBlockSignature;
} HEAP_EXTENDED_ENTRY, *PHEAP_EXTENDED_ENTRY;

typedef struct _HEAP_ENTRY {
	union {
		HEAP_UNPACKED_ENTRY UnpackedEntry;
		struct {
#if defined(_M_X64)
			PVOID PreviousBlockPrivateData;
			union {
				struct {
					UINT16 Size;
					UINT8 Flags;
					UINT8 SmallTagIndex;
				};
				struct {
					ULONG32 SubSegmentCode;
					UINT16 PreviousSize;
					union {
						UINT8 SegmentOffset;
						UINT8 LFHFlags;
					};
					UINT8 UnusedBytes;
				};
				UINT64 CompactHeader;
			};
#else
			UINT16 Size;
			UINT8 Flags;
			UINT8 SmallTagIndex;
#endif
		};
#if !defined(_M_X64)
		struct {
			ULONG32 SubSegmentCode;
			UINT16 PreviousSize;
			union {
				UINT8 SegmentOffset;
				UINT8 LFHFlags;
			};
			UINT8 UnusedBytes;
		};
#endif
		HEAP_EXTENDED_ENTRY ExtendedEntry;
		struct {
#if defined(_M_X64)
			PVOID Reserved;
			union {
				struct {
					UINT16 FunctionIndex;
					UINT16 ContextValue;
				};
				ULONG32 InterceptorValue;
			};
			UINT16 UnusedBytesLength;
			UINT8 EntryOffset;
			UINT8 ExtendedBlockSignature;
#else
			UINT16 FunctionIndex;
			UINT16 ContextValue;
#endif
		};
		struct {
#if defined(_M_X64)
			PVOID ReservedForAlignment;
			union {
				struct {
					ULONG32 Code1;
					union {
						struct {
							UINT16 Code2;
							UINT8 Code3;
							UINT8 Code4;
						};
						ULONG32 Code234;
					};
				};
				UINT64 AgregateCode;
			};
#else
			ULONG32 InterceptorValue;
			UINT16 UnusedBytesLength;
			UINT8 EntryOffset;
			UINT8 ExtendedBlockSignature;
#endif
		};
#if !defined(_M_X64)
		struct {
			ULONG32 Code1;
			union {
				struct {
					UINT16 Code2;
					UINT8 Code3;
					UINT8 Code4;
				};
				ULONG32 Code234;
			};
		};
		UINT64 AgregateCode;
#endif
	};
} HEAP_ENTRY, *PHEAP_ENTRY;

typedef struct _HEAP_LOCK {
	union {
		RTL_CRITICAL_SECTION CriticalSection;
		PVOID /*(ERESOURCE)*/ Resource;
	} Lock;
} HEAP_LOCK, *PHEAP_LOCK;

typedef struct _HEAP_TAG_ENTRY {
	ULONG32 Allocs;
	ULONG32 Frees;
	WPARAM Size;
	UINT16 TagIndex;
	UINT16 CreatorBackTraceIndex;
	WCHAR TagName[24];
#if defined(_M_X64)
	UINT8 _PADDING0_[4];
#endif
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;

typedef struct _HEAP_PSEUDO_TAG_ENTRY {
	ULONG32 Allocs;
	ULONG32 Frees;
	WPARAM Size;
} HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY;

typedef struct _HEAP_TUNING_PARAMETERS {
	ULONG32 CommittThresholdShift;
#if defined(_M_X64)
	UINT8 _PADDING0_[4];
#endif
	WPARAM MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;

typedef struct _RTL_HEAP_MEMORY_LIMIT_DATA {
	WPARAM CommitLimitBytes;
	WPARAM CommitLimitFailureCode;
	WPARAM MaxAllocationSizeBytes;
	WPARAM AllocationLimitFailureCode;
} RTL_HEAP_MEMORY_LIMIT_DATA, *PRTL_HEAP_MEMORY_LIMIT_DATA;

typedef struct _RTL_HP_ENV_HANDLE {
	PVOID h[2];
} RTL_HP_ENV_HANDLE, *PRTL_HP_ENV_HANDLE;

typedef struct _RTL_HP_SEG_ALLOC_POLICY {
	WPARAM MinLargePages;
	WPARAM MaxLargePages;
	UINT8 MinUtilization;
} RTL_HP_SEG_ALLOC_POLICY, *PRTL_HP_SEG_ALLOC_POLICY;

typedef enum _RTLP_HP_LOCK_TYPE {
	HeapLockPaged,
	HeapLockNonPaged,
	HeapLockTypeMax
} RTLP_HP_LOCK_TYPE;

typedef struct _HEAP_SUBALLOCATOR_CALLBACKS {
	PVOID Allocate;
	PVOID Free;
	PVOID Commit;
	PVOID Decommit;
	PVOID ExtendContext;
} HEAP_SUBALLOCATOR_CALLBACKS, *PHEAP_SUBALLOCATOR_CALLBACKS;

typedef struct _RTL_HP_VS_CONFIG {
	struct {
		ULONG PageAlignLargeAllocs : 1;
		ULONG FullDecommit : 1;
	} Flags;
} RTL_HP_VS_CONFIG, *PRTL_HP_VS_CONFIG;

typedef struct _HEAP_VS_SUBSEGMENT {
	LIST_ENTRY ListEntry;
	WPARAM CommitBitmap;
	WPARAM CommitLock;
	UINT16 Size;
	UINT16 Signature : 15;
	bool FullCommit : 1;
	WPARAM Spare;
} HEAP_VS_SUBSEGMENT, *PHEAP_VS_SUBSEGMENT;

typedef struct _HEAP_VS_CONTEXT {
	RTL_SRWLOCK Lock;
	WPARAM /*RTLP_HP_LOCK_TYPE*/ LockType;
	RTL_RB_TREE FreeChunkTree;
	LIST_ENTRY SubsegmentList;
	WPARAM TotalCommittedUnits;
	WPARAM FreeCommittedUnits;
	WPARAM /*HEAP_VS_DELAY_FREE_CONTEXT*/ DelayFreeContext[8]; // 0x40 Bytes
	PVOID BackendCtx;
	HEAP_SUBALLOCATOR_CALLBACKS Callbacks;
	RTL_HP_VS_CONFIG Config;
	UINT Flags;
	WPARAM Padding;
} HEAP_VS_CONTEXT, *PHEAP_VS_CONTEXT;

typedef struct _HEAP_VS_CHUNK_HEADER_SIZE {
	union {
		WPARAM HeaderBits;
		USHORT KeyUShort;
		ULONG KeyULong;
		struct {
			USHORT MemoryCost;
			USHORT UnsafeSize;
			USHORT UnsafePrevSize;
			UINT8 Allocated;
		};
	};
} HEAP_VS_CHUNK_HEADER_SIZE, *PHEAP_VS_CHUNK_HEADER_SIZE;

typedef struct _HEAP_VS_CHUNK_HEADER {
	HEAP_VS_CHUNK_HEADER_SIZE Sizes;
	union {
		ULONG EncodedSegmentPageOffset : 8;
		ULONG UnusedBytes : 1;
		ULONG SkipDuringWalk : 1;
		ULONG Spare : 22;
		ULONG AllocatedChunkBits;
	};
} HEAP_VS_CHUNK_HEADER, *PHEAP_VS_CHUNK_HEADER;

enum {
	PAGE_RANGE_FLAGS_LFH_SUBSEGMENT = 0x01,
	PAGE_RANGE_FLAGS_COMMITED		= 0x02,
	PAGE_RANGE_FLAGS_ALLOCATED		= 0x04,
	PAGE_RANGE_FLAGS_FIRST			= 0x08,
	PAGE_RANGE_FLAGS_VS_SUBSEGMENT	= 0x20 // LIES
};

typedef struct _HEAP_PAGE_RANGE_DESCRIPTOR {
	union {
		RTL_BALANCED_NODE TreeNode;
		struct {
			ULONG TreeSignature;
			ULONG UnusedBytes;
		};
		union {
			bool ExtraPresent;
			UINT16 Spare0 : 15;
		};
	};
	UCHAR RangeFlags;
	UCHAR CommittedPageCount;
	USHORT Spare;
	union {
		//_HEAP_DESCRIPTOR_KEY Key;
		UCHAR Align[3];
	};
	union {
		UCHAR UnitOffset;
		UCHAR UnitSize;
	};
} HEAP_PAGE_RANGE_DESCRIPTOR, *PHEAP_PAGE_RANGE_DESCRIPTOR;

typedef struct _HEAP_PAGE_SEGMENT {
	union {
		struct {
			LIST_ENTRY ListEntry;
			WPARAM Signature;
			PVOID SegmentCommitState;
			UCHAR UnusedWatermark;
		};
		HEAP_PAGE_RANGE_DESCRIPTOR DescArray[256];
	};
} HEAP_PAGE_SEGMENT, *PHEAP_PAGE_SEGMENT;

typedef struct _RTL_HP_LFH_CONFIG {
	USHORT MaxBlockSize;
	BYTE WitholdPageCrossingBlocks : 1;
} RTL_HP_LFH_CONFIG, *PRTL_HP_LFH_CONFIG;

typedef struct _HEAP_LFH_SUBSEGMENT_STAT {
	BYTE Index;
	BYTE Count;
} HEAP_LFH_SUBSEGMENT_STAT, *PHEAP_LFH_SUBSEGMENT_STAT;

typedef struct _HEAP_LFH_SUBSEGMENT_STATS {
	union {
		HEAP_LFH_SUBSEGMENT_STAT Buckets[4];
		UINT64 Stats;
	};
} HEAP_LFH_SUBSEGMENT_STATS, *PHEAP_LFH_SUBSEGMENT_STATS;

typedef struct _HEAP_LFH_SUBSEGMENT_OWNER {
	struct {
		BYTE IsBucket : 1;
		BYTE Spare0 : 7;
	};
	BYTE BucketIndex;
	union {
		BYTE SlotCount;
		BYTE SlotIndex;
	};
	BYTE Spare1;
	WPARAM AvailableSubsegmentCount;
	RTL_SRWLOCK Lock;
	LIST_ENTRY AvailableSubsegmentList;
	LIST_ENTRY FullSubsegmentList;
} HEAP_LFH_SUBSEGMENT_OWNER, *PHEAP_LFH_SUBSEGMENT_OWNER;

typedef struct _HEAP_LFH_FAST_REF {
	union {
		PVOID Target;
		WPARAM Value;
		UINT16 RefCount : 12;
	};
} HEAP_LFH_FAST_REF, *PHEAP_LFH_FAST_REF;

typedef struct _HEAP_LFH_AFFINITY_SLOT {
	HEAP_LFH_SUBSEGMENT_OWNER State;
	HEAP_LFH_FAST_REF ActiveSubsegment;
} HEAP_LFH_AFFINITY_SLOT, *PHEAP_LFH_AFFINITY_SLOT;

typedef struct _HEAP_LFH_BUCKET {
	HEAP_LFH_SUBSEGMENT_OWNER State;
	WPARAM TotalBlockCount;
	WPARAM TotalSubsegmentCount;
	UINT ReciprocalBlockSize;
	UINT8 Shift;
	UINT8 ContentionCount;
	WPARAM AffinityMappingLock;
	PUINT8 ProcAffinityMapping;
	PHEAP_LFH_AFFINITY_SLOT *AffinitySlots;
} HEAP_LFH_BUCKET, *PHEAP_LFH_BUCKET;

typedef struct _HEAP_LFH_CONTEXT {
	PVOID BackendCtx;
	HEAP_SUBALLOCATOR_CALLBACKS Callbacks;
	PUINT8 AffinityModArray;
	UINT8 MaxAffinity;
	UINT8 LockType;
	USHORT MemStatsOffset;
	RTL_HP_LFH_CONFIG Config;
	HEAP_LFH_SUBSEGMENT_STATS BucketStats;
	WPARAM SubsegmentCreationLock;
	WPARAM Padding[6];
	PHEAP_LFH_BUCKET Buckets[129];
} HEAP_LFH_CONTEXT, *PHEAP_LFH_CONTEXT;

typedef struct _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS {
	union {
		UINT32 EncodedData;
		struct {
			UINT16 BlockSize;
			UINT16 FirstBlockOffset;
		};
	};
} HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS, *PHEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS;

typedef struct _HEAP_LFH_SUBSEGMENT {
	LIST_ENTRY ListEntry;
	union {
		PHEAP_LFH_SUBSEGMENT_OWNER Owner;
		WPARAM /*HEAP_LFH_SUBSEGMENT_DELAY_FREE*/ DelayFree;
	};
	WPARAM CommitLock;
	union {
		struct {
			UINT16 FreeCount;
			UINT16 BlockCount;
		};
		union {
			SHORT InterlockedShort;
			LONG InterlockedLong;
		};
	};
	UINT16 FreeHint;
	BYTE Location;
	BYTE WitheldBlockCount;
	HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS BlockOffsets;
	BYTE CommitUnitShift;
	BYTE CommitUnitCount;
	UINT16 CommitStateOffset;
	WPARAM BlockBitmap[1];
} HEAP_LFH_SUBSEGMENT, *PHEAP_LFH_SUBSEGMENT;

typedef struct _HEAP_LARGE_ALLOC_DATA {
	RTL_BALANCED_NODE TreeNode;
	union {
		WPARAM VirtualAddess;
		UINT16 UnusedBytes;
	};
	union {
		UINT64 BitMask;
		union {
			bool ExtraPresent : 1;
			bool GuardPageCount : 1;
			UINT8 GuardPageAlignment : 6;
			UINT8 Spare : 4;
			UINT64 AllocatedPages : 52;
		};
	};
} HEAP_LARGE_ALLOC_DATA, *PHEAP_LARGE_ALLOC_DATA;

typedef struct _HEAP_OPPORTUNISTIC_LARGE_PAGE_STATS {
	WPARAM SmallPagesInUseWithinLarge;
	WPARAM OpportunisticLargePageCount;
} HEAP_OPPORTUNISTIC_LARGE_PAGE_STATS, *PHEAP_OPPORTUNISTIC_LARGE_PAGE_STATS;

typedef struct _HEAP_RUNTIME_MEMORY_STATS {
	WPARAM TotalReservedPages;
	WPARAM TotalCommittedPages;
	WPARAM FreeCommittedPages;
	WPARAM LfhFreeCommittedPages;
	HEAP_OPPORTUNISTIC_LARGE_PAGE_STATS LargePageStats[2];
	RTL_HP_SEG_ALLOC_POLICY LargePageUtilizationPolicy;
} HEAP_RUNTIME_MEMORY_STATS, *PHEAP_RUNTIME_MEMORY_STATS;

typedef struct _HEAP_SEG_CONTEXT {
	UINT64 SegmentMask;
	BYTE UnitShift;
	BYTE PagesPerUnitShift;
	BYTE FirstDescriptorIndex;
	BYTE CachedCommitSoftShift;
	BYTE CachedCommitHighShift;
	UINT16 Flags;
	UINT MaxAllocationSize;
	UINT16 OlpStatsOffset;
	UINT16 MemStatsOffset;
	PVOID LfhContext;
	PVOID VsContext;
	RTL_HP_ENV_HANDLE EnvHandle;
	PVOID Heap;
	WPARAM SegmentLock;
	LIST_ENTRY SegmentListHead;
	WPARAM SegmentCount;
	RTL_RB_TREE FreePageRanges;
	WPARAM FreeSegmentListLock;
	SINGLE_LIST_ENTRY FreeSegmentList[2];
	WPARAM Padding[7];
} HEAP_SEG_CONTEXT, *PHEAP_SEG_CONTEXT;

typedef struct _SEGMENT_HEAP {
	RTL_HP_ENV_HANDLE EnvHandle;
	ULONG Signature;
	ULONG GlobalFlags;
	ULONG Interceptor;
	USHORT ProcessHeapListIndex;
	USHORT AllocatedFromMetadata : 1;
	union {
		RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;
		struct {
			UINT64 ReservedMustBeZero1;
			PVOID UserContext;
			PVOID ReservedMustBeZero2;
			PVOID Spare;
		};
	};
	RTL_SRWLOCK LargeMetadataLock;
	RTL_RB_TREE LargeAllocMetadata; // Tree of HEAP_LARGE_ALLOC_DATA
	WPARAM LargeReservedPages;
	WPARAM LargeCommittedPages;
	RTL_RUN_ONCE StackTraceInitVar;
	WPARAM Padding[2];
	HEAP_RUNTIME_MEMORY_STATS MemStats;
	UINT16 GlobalLockCount;
	ULONG GlobalLockOwner;
	RTL_SRWLOCK ContextExtendLock;
	PUINT8 AllocatedBase;
	PUINT8 UncommittedBase;
	PUINT8 ReservedLimit;
	HEAP_SEG_CONTEXT SegContexts[2];
	HEAP_VS_CONTEXT VsContext;
	HEAP_LFH_CONTEXT LfhContext;
} SEGMENT_HEAP, *PSEGMENT_HEAP;

typedef struct _HEAP_SEGMENT {
	HEAP_ENTRY Entry;
	ULONG32 SegmentSignature;
	ULONG32 SegmentFlags;
	LIST_ENTRY SegmentListEntry;
	PHEAP Heap;
	PVOID BaseAddress;
	ULONG32 NumberOfPages;
#if defined(_M_X64)
	UINT8 _PADDING0_[4];
#endif
	PHEAP_ENTRY FirstEntry;
	PHEAP_ENTRY LastValidEntry;
	ULONG32 NumberOfUnCommittedPages;
	ULONG32 NumberOfUnCommittedRanges;
	UINT16 SegmentAllocatorBackTraceIndex;
	UINT16 Reserved;
#if defined(_M_X64)
	UINT8 _PADDING1_[4];
#endif
	LIST_ENTRY UCRSegmentList;
} HEAP_SEGMENT, *PHEAP_SEGMENT;

typedef struct _HEAP {
	union {
		HEAP_SEGMENT Segment;
		struct {
			HEAP_ENTRY Entry;
			ULONG32 SegmentSignature;
			ULONG32 SegmentFlags;
			LIST_ENTRY SegmentListEntry;
			PHEAP Heap;
			PVOID BaseAddress;
			ULONG32 NumberOfPages;
			PHEAP_ENTRY FirstEntry;
			PHEAP_ENTRY LastValidEntry;
			ULONG32 NumberOfUnCommittedPages;
			ULONG32 NumberOfUnCommittedRanges;
			UINT16 SegmentAllocatorBackTraceIndex;
			UINT16 Reserved;
			LIST_ENTRY UCRSegmentList;
		};
	};
	ULONG32 Flags;
	ULONG32 ForceFlags;
	ULONG32 CompatibilityFlags;
	ULONG32 EncodeFlagMask;
	HEAP_ENTRY Encoding;
	ULONG32 Interceptor;
	ULONG32 VirtualMemoryThreshold;
	ULONG32 Signature;
#if defined(_M_X64)
	UINT8 _PADDING0_[4];
#endif
	WPARAM SegmentReserve;
	WPARAM SegmentCommit;
	WPARAM DeCommitFreeBlockThreshold;
	WPARAM DeCommitTotalFreeThreshold;
	WPARAM TotalFreeSize;
	WPARAM MaximumAllocationSize;
	UINT16 ProcessHeapsListIndex;
	UINT16 HeaderValidateLength;
#if defined(_M_X64)
	UINT8 _PADDING1_[4];
#endif
	PVOID HeaderValidateCopy;
	UINT16 NextAvailableTagIndex;
	UINT16 MaximumTagIndex;
#if defined(_M_X64)
	UINT8 _PADDING2_[4];
#endif
	PHEAP_TAG_ENTRY TagEntries;
	LIST_ENTRY UCRList;
	WPARAM AlignRound;
	WPARAM AlignMask;
	LIST_ENTRY VirtualAllocdBlocks;
	LIST_ENTRY SegmentList;
	UINT16 AllocatorBackTraceIndex;
	UINT8 _PADDING03_[2];
	ULONG32 NonDedicatedListLength;
	PVOID BlocksIndex;
	PVOID UCRIndex;
	PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
	LIST_ENTRY FreeLists;
	PHEAP_LOCK LockVariable;
	LONG32 (WINAPI * CommitRoutine) (PVOID, PVOID *, WPARAM *);
	RTL_RUN_ONCE StackTraceInitVar;
	RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;
	PVOID FrontEndHeap;
	UINT16 FrontHeapLockCount;
	UINT8 FrontEndHeapType;
	UINT8 RequestedFrontEndHeapType;
#if defined(_M_X64)
	UINT8 _PADDING4_[4];
#endif
	PUINT16 FrontEndHeapUsageData;
	UINT16 FrontEndHeapMaximumIndex;
#if defined(_M_X64)
	UINT8 FrontEndHeapStatusBitmap[129];
#else
	UINT8 FrontEndHeapStatusBitmap[257];
#endif
#if defined(_M_X64)
	UINT8 _PADDING5_[5];
#else
	UINT8 _PADDING1_[1];
#endif
	HEAP_COUNTERS Counters;
	HEAP_TUNING_PARAMETERS TuningParameters;
} HEAP, *PHEAP;

typedef struct _HEAP_ENTRY_EXTRA {
	union {
		struct {
			UINT16 AllocatorBackTraceIndex;
			UINT16 TagIndex;
#if defined(_M_X64)
			UINT8 _PADDING0_[4];
#endif
			WPARAM Settable;
		};
#if defined(_M_X64)
		struct {
			UINT64 ZeroInit;
			UINT64 ZeroInit1;
		};
#else
		UINT64 ZeroInit;
#endif
	};
} HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA;

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY {
	LIST_ENTRY Entry;
	HEAP_ENTRY_EXTRA ExtraStuff;
	WPARAM CommitSize;
	WPARAM ReserveSize;
	HEAP_ENTRY BusyBlock;
} HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY;

typedef struct _LFH_BLOCK_ZONE {
	LIST_ENTRY ListEntry;
	LONG NextIndex;
	/*	// Win 7
	PVOID FreePointer;
	PVOID Limit;
	*/
} LFH_BLOCK_ZONE, *PLFH_BLOCK_ZONE;

typedef struct _HEAP_USERDATA_OFFSETS {
	union {
		UINT32 StrideAndOffset;
		struct {
			UINT16 FirstAllocationOffset;
			UINT16 BlockStride;
		};
	};
} HEAP_USERDATA_OFFSETS, *PHEAP_USERDATA_OFFSETS;

typedef struct _RTL_BITMAP_EX {
	WPARAM SizeOfBitMap;
	WPARAM *Buffer;
} RTL_BITMAP_EX, *PRTL_BITMAP_EX;

typedef struct _HEAP_USERDATA_HEADER {
	union {
		SINGLE_LIST_ENTRY SFreeListEntry;
		PHEAP_SUBSEGMENT SubSegment;
	};
	PVOID Reserved;
	union {
		UINT32 SizeIndexAndPadding;
		struct {
			UCHAR SizeIndex;
			UCHAR GuardPagePresent;
			UINT16 PaddingBytes;
		};
	};
	ULONG Signature;
	HEAP_USERDATA_OFFSETS EncodedOffsets;
	RTL_BITMAP_EX BusyBitmap;
	WPARAM BitmapData;
} HEAP_USERDATA_HEADER, *PHEAP_USERDATA_HEADER;


typedef struct _HEAP_SUBSEGMENT *PHEAP_SUBSEGMENT;
typedef struct _HEAP_LOCAL_SEGMENT_INFO {
	PHEAP_LOCAL_DATA LocalData;
	PHEAP_SUBSEGMENT ActiveSubsegment;
	PHEAP_SUBSEGMENT CachedItems[16];
	SLIST_HEADER SListHeader;
	HEAP_BUCKET_COUNTERS Counters;
	ULONG LastOpSequence;
	UINT16 BucketIndex;
	UINT16 LastUsed;
	UINT16 NoThrashCount;
} HEAP_LOCAL_SEGMENT_INFO, *PHEAP_LOCAL_SEGMENT_INFO;

typedef struct _HEAP_SUBSEGMENT {
	PHEAP_LOCAL_SEGMENT_INFO LocalInfo;
	PHEAP_USERDATA_HEADER UserBlocks;
	SLIST_HEADER DelayFreeList;
	INTERLOCK_SEQ AggregateExchg;
	union {
		struct {
			WORD BlockSize;
			WORD Flags;
			WORD BlockCount;
			UINT8 SizeIndex;
			UINT8 AffinityIndex;
		};
		ULONG Alignment[2];
	};
	ULONG Lock;
	SINGLE_LIST_ENTRY SFreeListEntry;
} HEAP_SUBSEGMENT, *PHEAP_SUBSEGMENT;

typedef struct _HEAP_LFH_MEM_POLICIES {
	union {
		ULONG AllPolicies;
		union {
			UINT8 DisableAffinity : 1;
			UINT8 SlowSubsegmentGrowth : 1;
			ULONG Spare : 30;
		};
	};
} HEAP_LFH_MEM_POLICIES, *PHEAP_LFH_MEM_POLICIES;

typedef struct _HEAP_LOCAL_DATA {
	SLIST_HEADER DeletedSubSegments;
	PLFH_BLOCK_ZONE CrtZone;
	PLFH_HEAP LowFragHeap;
	ULONG Sequence;
	//HEAP_LOCAL_SEGMENT_INFO SegmentInfo[128]; // Only on Win7
} HEAP_LOCAL_DATA, *PHEAP_LOCAL_DATA;

typedef struct _HEAP_BUCKET {
	WORD BlockUnits;
	UINT8 SizeIndex;
	union {
		BYTE Flags;
		union {
			BYTE UseAffinity : 1;
			BYTE DebugFlags : 2;
		};
	};
} HEAP_BUCKET, *PHEAP_BUCKET;

typedef struct _HEAP_BUCKET_RUN_INFO {
	union {
		struct {
			ULONG Bucket;
			ULONG RunLength;
		};
		UINT64 Aggregate64;
	};
} HEAP_BUCKET_RUN_INFO, *PHEAP_BUCKET_RUN_INFO;

typedef struct _USER_MEMORY_CACHE_ENTRY {
	SLIST_HEADER UserBlocks;
	ULONG AvailableBlocks;
	ULONG MinimumDepth;
	ULONG CacheShiftThreshold;
	USHORT Allocations;
	USHORT Frees;
	USHORT CacheHits;
} USER_MEMORY_CACHE_ENTRY, *PUSER_MEMORY_CACHE_ENTRY;

typedef struct _LFH_HEAP {
	RTL_SRWLOCK Lock;
	LIST_ENTRY SubSegmentZones;
	PVOID Heap;
	PVOID NextSegmentInfoArrayAddress;
	PVOID FirstUncommittedAddress;
	PVOID ReservedAddressLimit;
	ULONG SegmentCreate;
	ULONG SegmentDelete;
	ULONG MinimumCacheDepth;
	ULONG CacheShiftThreshold;
	WPARAM SizeInCache;
	HEAP_BUCKET_RUN_INFO RunInfo;
	USER_MEMORY_CACHE_ENTRY UserBlockCache[12];
	HEAP_LFH_MEM_POLICIES MemoryPolicies;
	HEAP_BUCKET Buckets[129];
	PHEAP_LOCAL_SEGMENT_INFO SegmentInfoArrays[129];
	PHEAP_LOCAL_SEGMENT_INFO AffinitizedInfoArrays[129];
	PSEGMENT_HEAP SegmentAllocator;
	HEAP_LOCAL_DATA LocalData[1];
} LFH_HEAP, *PLFH_HEAP;

typedef struct _HeapBlockBasicInfo {
	WPARAM size;
	WPARAM flags;
	WPARAM extra;
	WPARAM address;
} HeapBlockBasicInfo, *PHeapBlockBasicInfo;

typedef struct _HeapBlockExtraInfo { // think of extra stuff to put here
	WPARAM heap;
	WPARAM segment;
	WPARAM unusedBytes;
	USHORT granularity;
} HeapBlockExtraInfo, *PHeapBlockExtraInfo;

typedef struct _HeapBlock {
	ULONG_PTR dwAddress;
	SIZE_T dwSize;
	DWORD dwFlags;
	SIZE_T index;
	PHeapBlockExtraInfo extraInfo;
} HeapBlock, *PHeapBlock;

typedef struct _DEBUG_BUFFER {
	HANDLE SectionHandle;
	PVOID SectionBase;
	PVOID RemoteSectionBase;
	WPARAM SectionBaseDelta;
	HANDLE EventPairHandle;
	HANDLE RemoteEventPairHandle;
	HANDLE RemoteProcessId;
	HANDLE RemoteThreadHandle;
	ULONG InfoClassMask;
	SIZE_T SizeOfInfo;
	SIZE_T AllocatedSize;
	SIZE_T SectionSize;
	PVOID ModuleInformation;
	PVOID BackTraceInformation;
	PVOID HeapInformation;
	PVOID LockInformation;
	PVOID SpecificHeap;
	HANDLE RemoteProcessHandle;
	PVOID VerifierOptions;
	PVOID ProcessHeap;
	HANDLE CriticalSectionHandle;
	HANDLE CriticalSectionOwnerThread;
	PVOID Reserved[4];
} DEBUG_BUFFER, *PDEBUG_BUFFER;


typedef struct _DEBUG_HEAP_INFORMATION {
	PVOID Base;
	DWORD Flags;
	USHORT Granularity;
	USHORT CreatorBackTraceIndex;
	SIZE_T Allocated;
	SIZE_T Committed;
	DWORD TagCount;
	DWORD BlockCount;
	DWORD PseudoTagCount;
	DWORD PseudoTagGranularity;
	DWORD Reserved[5];
	PVOID Tags;
	PVOID Blocks;
} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION;

typedef struct _HeapInformation {
	DWORD count;
	DEBUG_HEAP_INFORMATION heaps[/* count */];
} HeapInformation, *PHeapInformation;

PDEBUG_BUFFER (NTAPI *RtlCreateQueryDebugBuffer)(
	IN DWORD Size,
	IN BOOLEAN EventPair
);

NTSTATUS (NTAPI *RtlQueryProcessDebugInformation)(
	IN DWORD ProcessId,
	IN DWORD DebugInfoClassMask,
	IN OUT PDEBUG_BUFFER DebugBuffer
);

NTSTATUS (NTAPI *RtlDestroyQueryDebugBuffer)(
	IN PDEBUG_BUFFER DebugBuffer
);

__kernel_entry NTSTATUS (NTAPI *w32_NtQueryInformationProcess)(
  IN HANDLE           ProcessHandle,
  IN PROCESSINFOCLASS ProcessInformationClass,
  OUT PVOID           ProcessInformation,
  IN ULONG            ProcessInformationLength,
  OUT PULONG          ReturnLength
);
#endif