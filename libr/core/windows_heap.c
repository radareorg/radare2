#include <r_core.h>
#include <TlHelp32.h>
#include <windows_heap.h>
#include "..\..\debug\p\native\maps\windows_maps.h"

/*
*	Viewer discretion advised: Spaghetti code ahead
*	Some Code references:
*	https://securityxploded.com/enumheaps.php
*	https://bitbucket.org/evolution536/crysearch-memory-scanner/
*	https://processhacker.sourceforge.io
*	http://www.tssc.de/winint
*	https://www.nirsoft.net/kernel_struct/vista/
*	https://github.com/yoichi/HeapStat/blob/master/heapstat.cpp
*	https://doxygen.reactos.org/
*
*	References:
*	Windows NT(2000) Native API Reference (Book)
*	Papers: 
*	http://illmatics.com/Understanding_the_LFH.pdf
*	http://illmatics.com/Windows%208%20Heap%20Internals.pdf
*	https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf
*
*	This code has 2 different approaches to getting the heap info:
*		1) Calling InitHeapInfo with both PDI_HEAPS and PDI_HEAP_BLOCKS.
*			This will fill a buffer with HeapBlockBasicInfo like structures which
*			is then walked through by calling GetFirstHeapBlock and subsequently GetNextHeapBlock
*			(see 1st link). This approach is the more generic one as it uses Windows functions.
*			Unfortunately it fails to offer more detailed information about each block (although it is possible to get this info later) and
*			also fails misteriously once the count of allocated blocks reach a certain threshold (1mil or so) or if segment heap is active for the
*			program (in this case everything locks in the next call for the function)
*		2) In case 1 fails, Calling GetHeapBlocks, which will manually read and parse (poorly :[ ) each block.
*			First it calls InitHeapInfo	with only the PDI_HEAPS flag, with the only objective of getting a list of heap header addresses. It will then
*			do the job that InitHeapInfo would do if it was called with PDI_HEAP_BLOCKS as well, filling a buffer with HeapBlockBasicInfo structures that
*			can also be walked with GetFirstHeapBlock and GetNextHeapBlock (and HeapBlockExtraInfo when needed).
*
*	TODO:
*		Var to select algorithm?
*		x86 vs x64 vs WOW64
*		Graphs
*		Use the flags field for extra info
*		Print structures
*		Make sure GetHeapBlocks actually works
*		Maybe instead of using hardcoded structs we can get the offsets from ntdll.pdb
*/

#define PDI_MODULES				0x01
#define PDI_HEAPS				0x04
#define PDI_HEAP_TAGS			0x08
#define PDI_HEAP_BLOCKS			0x10
#define PDI_HEAP_ENTRIES_EX		0x200

#define CHECK_INFO(heapInfo)\
	if (!heapInfo) {\
		eprintf ("It wasn't possible to get the heap information\n");\
		return;\
	}\
	if (!heapInfo->count) {\
		r_cons_print ("No heaps for this process\n");\
		return;\
	}

#define UPDATE_FLAGS(hb, flags)\
	if ((flags & 0xf1) || (flags & 0x0200)) {\
		hb->dwFlags = LF32_FIXED;\
	} else if ((flags & 0x20)) {\
		hb->dwFlags = LF32_MOVEABLE;\
	} else if ((flags & 0x0100)) {\
		hb->dwFlags = LF32_FREE;\
	}

static bool init_func() {
	HANDLE ntdll = LoadLibrary (TEXT ("ntdll.dll"));
	if (!ntdll) {
		return false;
	}
	if (!RtlCreateQueryDebugBuffer) {
		RtlCreateQueryDebugBuffer = GetProcAddress (ntdll, "RtlCreateQueryDebugBuffer");
	}
	if (!RtlQueryProcessDebugInformation) {
		RtlQueryProcessDebugInformation = GetProcAddress (ntdll, "RtlQueryProcessDebugInformation");
	}
	if (!RtlDestroyQueryDebugBuffer) {
		RtlDestroyQueryDebugBuffer = GetProcAddress (ntdll, "RtlDestroyQueryDebugBuffer");
	}
	return true;
}

static bool is_segment_heap(HANDLE h_proc, PVOID heapBase) {
	HEAP heap;
	if (ReadProcessMemory (h_proc, heapBase, &heap, sizeof (HEAP), NULL)) {
		if (heap.SegmentSignature == 0xddeeddee) {
			return true;
		}
	}
	return false;
}

// These functions are basically Heap32First and Heap32Next but faster
static bool GetFirstHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb) {
	r_return_val_if_fail (heapInfo && hb, false);
	PHeapBlockBasicInfo block;

	hb->index = 0;
	hb->dwAddress = 0;
	hb->dwFlags = 0;
	hb->extraInfo = NULL;

	block = (PHeapBlockBasicInfo)heapInfo->Blocks;
	SIZE_T index = hb->index;
	do {
		if (index > heapInfo->BlockCount) return false;
		hb->dwAddress = (void *)block[index].address;
		hb->dwSize = block->size;
		if (block[index].extra & EXTRA_FLAG) {
			PHeapBlockExtraInfo extra = (PHeapBlockExtraInfo)(block[index].extra & ~EXTRA_FLAG);
			hb->dwSize -= extra->unusedBytes;
			hb->extraInfo = extra;
			(WPARAM)hb->dwAddress += extra->granularity;
		} else {
			(WPARAM)hb->dwAddress += heapInfo->Granularity;
			hb->extraInfo = NULL;
		}
		index++;
	} while (block[index].flags & 2);

	hb->index = index;

	USHORT flags = block[hb->index].flags;
	UPDATE_FLAGS (hb, flags);
	return true;
}

static bool GetNextHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb) {
	r_return_val_if_fail (heapInfo && hb, false);
	PHeapBlockBasicInfo block;

	block = (PHeapBlockBasicInfo)heapInfo->Blocks;
	SIZE_T index = hb->index;

	if (index > heapInfo->BlockCount) {
		return false;
	}

	if (block[index].flags & 2) {
		do {
			if (index > heapInfo->BlockCount) {
				return false;
			}

			// new address = curBlockAddress + Granularity;
			hb->dwAddress = (void *)(block[index].address + heapInfo->Granularity);

			index++;
			hb->dwSize = block->size;
		} while (block[index].flags & 2);
		hb->index = index;
	} else {
		hb->dwSize = block[index].size;
		if (block[index].extra & EXTRA_FLAG) {
			PHeapBlockExtraInfo extra = (PHeapBlockExtraInfo)(block[index].extra & ~EXTRA_FLAG);
			hb->extraInfo = extra;
			hb->dwSize -= extra->unusedBytes;
			hb->dwAddress = (void *)(block[index].address + extra->granularity);
		} else {
			hb->extraInfo = NULL;
			(WPARAM)hb->dwAddress += hb->dwSize;
		}
		hb->index++;
	}

	USHORT flags = block[index].flags;
	UPDATE_FLAGS (hb, flags);

	return true;
}

static void free_extra_info(PDEBUG_HEAP_INFORMATION heap) {
	r_return_if_fail (heap);
	HeapBlock hb;
	if (GetFirstHeapBlock (heap, &hb)) {
		do {
			R_FREE (hb.extraInfo);
		} while (GetNextHeapBlock (heap, &hb));
	}
}

static bool DecodeHeapEntry(PHEAP heap, PHEAP_ENTRY entry) {
#if defined(_M_X64)
	(WPARAM)entry += sizeof (PVOID);
#endif
	if (heap->EncodeFlagMask && (*(UINT32 *)entry & heap->EncodeFlagMask)) {
#if defined(_M_X64)
		(WPARAM)heap += sizeof (PVOID);
#endif
		*(WPARAM *)entry ^= *(WPARAM *)&heap->Encoding;
	}
	return !(((BYTE *)entry)[0] ^ ((BYTE *)entry)[1] ^ ((BYTE *)entry)[2] ^ ((BYTE *)entry)[3]);
}

// Is this right?
static bool DecodeLFHEntry(PHEAP heap, PHEAP_ENTRY entry, PHEAP_USERDATA_HEADER userBlocks, WPARAM key, WPARAM addr) {
#if defined(_M_X64)
	(WPARAM)entry += sizeof (PVOID);
#endif
	if (heap->EncodeFlagMask) {
		*(DWORD *)entry ^= PtrToInt (heap->BaseAddress) ^ (DWORD)(((DWORD)addr - PtrToInt (userBlocks)) << 0xC) ^ (DWORD)key ^ ((DWORD)addr >> 4);
	}
	return !(((BYTE *)entry)[0] ^ ((BYTE *)entry)[1] ^ ((BYTE *)entry)[2] ^ ((BYTE *)entry)[3]);
}

/*
*	This function may fail with PDI_HEAP_BLOCKS if:
*		There's too many allocations
*		The Segment Heap is activated (will block next time called)
*		Notes:
*			Some LFH allocations seem misaligned
*/
static PDEBUG_BUFFER InitHeapInfo(DWORD pid, DWORD mask) {
	// Make sure it is not segment heap to avoid lockups
	if (mask & PDI_HEAP_BLOCKS) {
		PDEBUG_BUFFER db = InitHeapInfo (pid, PDI_HEAPS);
		if (db) {
			HANDLE h_proc = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			PHeapInformation heaps = db->HeapInformation;
			for (int i = 0; i < heaps->count; i++) {
				DEBUG_HEAP_INFORMATION heap = heaps->heaps[i];
				if (is_segment_heap (h_proc, heap.Base)) {
					RtlDestroyQueryDebugBuffer (db);
					return NULL;
				}
			}
			RtlDestroyQueryDebugBuffer (db);
		} else {
			return NULL;
		}
	}
	int res;
	PDEBUG_BUFFER db = RtlCreateQueryDebugBuffer (0, FALSE);
	res = RtlQueryProcessDebugInformation (pid, mask, db);
	if (res) {
		// why after it fails the first time it blocks on the second? Thats annoying
		// It stops blocking if i pause radare in the debugger. is it a race?
		// why it fails with 1000000 allocs? also with processes with segment heap enabled?
		RtlDestroyQueryDebugBuffer (db);
		r_sys_perror ("InitHeapInfo");
		return NULL;
	}
	return db;
}

#define GROW_BLOCKS()\
	if (allocated <= count * sizeof (HeapBlockBasicInfo)) {\
		SIZE_T old_alloc = allocated;\
		allocated *= 2;\
		PVOID tmp = blocks;\
		blocks = realloc (blocks, allocated);\
		if (!blocks) {\
			free (tmp);\
			goto err;\
		}\
		memset ((BYTE *)blocks + old_alloc, 0, old_alloc);\
	}

#define GROW_PBLOCKS()\
	if (*allocated <= *count * sizeof (HeapBlockBasicInfo)) {\
		SIZE_T old_alloc = *allocated;\
		*allocated *= 2;\
		PVOID tmp = *blocks;\
		tmp = realloc (*blocks, *allocated);\
		if (!tmp) {\
			return false;\
		}\
		*blocks = tmp;\
		memset ((BYTE *)(*blocks) + old_alloc, 0, old_alloc);\
	}

static bool __lfh_segment_loop(HANDLE h_proc, PHeapBlockBasicInfo *blocks, SIZE_T *allocated, WPARAM lfhKey, WPARAM *count, WPARAM first, WPARAM next) {
	while ((first != next) && next) {
		HEAP_LFH_SUBSEGMENT subsegment;
		ReadProcessMemory (h_proc, (void *)next, &subsegment, sizeof (HEAP_LFH_SUBSEGMENT), NULL);
		subsegment.BlockOffsets.EncodedData ^= (DWORD)lfhKey ^ ((DWORD)next >> 0xC);
		WPARAM mask = 1, offset = 0;
		for (int l = 0; l < subsegment.BlockCount; l++) {
			if (!mask) {
				mask = 1;
				offset++;
				ReadProcessMemory (h_proc, (WPARAM *)(next + offsetof (HEAP_LFH_SUBSEGMENT, BlockBitmap)) + offset,
					&subsegment.BlockBitmap, sizeof (WPARAM), NULL);
			}
			if (subsegment.BlockBitmap[0] & mask) {
				GROW_PBLOCKS ();
				WPARAM off = subsegment.BlockOffsets.FirstBlockOffset + l * subsegment.BlockOffsets.BlockSize;
				(*blocks)[*count].address = next + off;
				(*blocks)[*count].size = subsegment.BlockOffsets.BlockSize;
				(*blocks)[*count].flags = 1 | SEGMENT_HEAP_BLOCK | LFH_BLOCK;
				PHeapBlockExtraInfo extra = calloc (1, sizeof (HeapBlockExtraInfo));
				if (!extra) {
					return false;
				}
				extra->segment = next;
				extra->granularity = sizeof (HEAP_ENTRY);
				(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
				*count += 1;
			}
			mask <<= 2;
		}
		next = (WPARAM)subsegment.ListEntry.Flink;
	}
	return true;
}

static bool GetSegmentHeapBlocks(HANDLE h_proc, PVOID heapBase, PHeapBlockBasicInfo *blocks, WPARAM *count, SIZE_T *allocated, WPARAM ntdllOffset) {
	r_return_val_if_fail (h_proc && blocks && count && allocated, false);
	WPARAM bytesRead;
	SEGMENT_HEAP segheapHeader;
	ReadProcessMemory (h_proc, heapBase, &segheapHeader, sizeof (SEGMENT_HEAP), &bytesRead);

	if (segheapHeader.Signature != 0xddeeddee) {
		return false;
	}

	WPARAM RtlpHpHeapGlobalsOffset = ntdllOffset + 0x44A0; // ntdll!RtlpHpHeapGlobals

	WPARAM lfhKey;
	WPARAM lfhKeyLocation = RtlpHpHeapGlobalsOffset + sizeof (WPARAM);
	if (!ReadProcessMemory (h_proc, (PVOID)lfhKeyLocation, &lfhKey, sizeof (WPARAM), &bytesRead)) {
		r_sys_perror ("ReadProcessMemory");
		eprintf ("LFH key not found.\n");
		return false;
	}

	// LFH
	byte numBuckets = _countof (segheapHeader.LfhContext.Buckets);
	for (int j = 0; j < numBuckets; j++) {
		if ((WPARAM)segheapHeader.LfhContext.Buckets[j] & 1) continue;
		HEAP_LFH_BUCKET bucket;
		ReadProcessMemory (h_proc, segheapHeader.LfhContext.Buckets[j], &bucket, sizeof (HEAP_LFH_BUCKET), &bytesRead);
		HEAP_LFH_AFFINITY_SLOT affinitySlot, *paffinitySlot;
		ReadProcessMemory (h_proc, bucket.AffinitySlots, &paffinitySlot, sizeof (PHEAP_LFH_AFFINITY_SLOT), &bytesRead);
		bucket.AffinitySlots++;
		ReadProcessMemory (h_proc, paffinitySlot, &affinitySlot, sizeof (HEAP_LFH_AFFINITY_SLOT), &bytesRead);
		WPARAM first = (WPARAM)paffinitySlot + offsetof (HEAP_LFH_SUBSEGMENT_OWNER, AvailableSubsegmentList);
		WPARAM next = (WPARAM)affinitySlot.State.AvailableSubsegmentList.Flink;
		if (!__lfh_segment_loop (h_proc, blocks, allocated, lfhKey, count, first, next)) {
			return false;
		}
		first = (WPARAM)paffinitySlot + offsetof (HEAP_LFH_SUBSEGMENT_OWNER, FullSubsegmentList);
		next = (WPARAM)affinitySlot.State.FullSubsegmentList.Flink;
		if (!__lfh_segment_loop (h_proc, blocks, allocated, lfhKey, count, first, next)) {
			return false;
		}
	}

	// Large Blocks
	if (segheapHeader.LargeAllocMetadata.Root) {
		PRTL_BALANCED_NODE node = malloc (sizeof (RTL_BALANCED_NODE));
		RStack *s = r_stack_new (segheapHeader.LargeReservedPages);
		PRTL_BALANCED_NODE curr = segheapHeader.LargeAllocMetadata.Root;
		do { // while (!r_stack_is_empty(s));
			GROW_PBLOCKS ();
			while (curr) {
				r_stack_push (s, curr);
				ReadProcessMemory (h_proc, curr, node, sizeof (RTL_BALANCED_NODE), &bytesRead);
				curr = node->Left;
			};
			curr = (PRTL_BALANCED_NODE)r_stack_pop (s);
			HEAP_LARGE_ALLOC_DATA entry;
			ReadProcessMemory (h_proc, curr, &entry, sizeof (HEAP_LARGE_ALLOC_DATA), &bytesRead);
			(*blocks)[*count].address = entry.VirtualAddess - entry.UnusedBytes;
			(*blocks)[*count].flags = 1 | SEGMENT_HEAP_BLOCK | LARGE_BLOCK;
			(*blocks)[*count].size = ((entry.AllocatedPages >> 12) << 12);
			PHeapBlockExtraInfo extra = calloc (1, sizeof (HeapBlockExtraInfo));
			extra->unusedBytes = entry.UnusedBytes;
			ReadProcessMemory(h_proc, (void *)(*blocks)[*count].address, &extra->granularity, sizeof (USHORT), &bytesRead);
			(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
			curr = entry.TreeNode.Right;
			*count += 1;
		} while (curr || !r_stack_is_empty(s));
		r_stack_free (s);
		free (node);
	}

	WPARAM RtlpHpHeapGlobal;
	ReadProcessMemory (h_proc, (PVOID)(RtlpHpHeapGlobalsOffset), &RtlpHpHeapGlobal, sizeof (WPARAM), &bytesRead);
	// Backend Blocks (And VS)
	for (int i = 0; i < 2; i++) {
		HEAP_SEG_CONTEXT ctx = segheapHeader.SegContexts[i];
		WPARAM ctxFirstEntry = (WPARAM)heapBase + offsetof (SEGMENT_HEAP, SegContexts) + sizeof (HEAP_SEG_CONTEXT) * i + offsetof (HEAP_SEG_CONTEXT, SegmentListHead);
		HEAP_PAGE_SEGMENT pageSegment;
		WPARAM currPageSegment = (WPARAM)ctx.SegmentListHead.Flink;
		do {
			if (!ReadProcessMemory (h_proc, (PVOID)currPageSegment, &pageSegment, sizeof (HEAP_PAGE_SEGMENT), &bytesRead)) {
				break;
			}
			for (int j = 2; j < 256; j++) {
				if ((pageSegment.DescArray[j].RangeFlags &
					(PAGE_RANGE_FLAGS_FIRST | PAGE_RANGE_FLAGS_ALLOCATED)) ==
					(PAGE_RANGE_FLAGS_FIRST | PAGE_RANGE_FLAGS_ALLOCATED)) {
					GROW_PBLOCKS ();
					(*blocks)[*count].address = currPageSegment + j * 0x1000;
					(*blocks)[*count].size = pageSegment.DescArray[j].UnitSize * 0x1000;
					(*blocks)[*count].flags = SEGMENT_HEAP_BLOCK | 1;
					PHeapBlockExtraInfo extra = calloc (1, sizeof (HeapBlockExtraInfo));
					extra->segment = currPageSegment;
					extra->unusedBytes = pageSegment.DescArray[j].UnusedBytes;
					(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
					*count += 1;
				}
				// Hack (i dont know if all blocks like this are VS or not)
				if (pageSegment.DescArray[j].RangeFlags & 0xF && pageSegment.DescArray[j].UnusedBytes == 0x1000) {
					HEAP_VS_SUBSEGMENT vsSubsegment;
					WPARAM start, from = currPageSegment + j * 0x1000;
					ReadProcessMemory (h_proc, (PVOID)from, &vsSubsegment, sizeof (HEAP_VS_SUBSEGMENT), &bytesRead);
					// Walk through subsegment
					start = from += sizeof (HEAP_VS_SUBSEGMENT);
					while (from < (WPARAM)start + vsSubsegment.Size * sizeof (HEAP_VS_CHUNK_HEADER)) {
						HEAP_VS_CHUNK_HEADER vsChunk;
						ReadProcessMemory (h_proc, (PVOID)from, &vsChunk, sizeof (HEAP_VS_CHUNK_HEADER), &bytesRead);
						vsChunk.Sizes.HeaderBits ^= from ^ RtlpHpHeapGlobal;
						WPARAM sz = vsChunk.Sizes.UnsafeSize * sizeof (HEAP_VS_CHUNK_HEADER);
						if (vsChunk.Sizes.Allocated) {
							GROW_PBLOCKS ();
							(*blocks)[*count].address = from;
							(*blocks)[*count].size = sz;
							(*blocks)[*count].flags = VS_BLOCK | SEGMENT_HEAP_BLOCK | 1;
							PHeapBlockExtraInfo extra = calloc (1, sizeof (HeapBlockExtraInfo));
							extra->granularity = sizeof (HEAP_VS_CHUNK_HEADER) * 2;
							(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
							*count += 1;
						}
						from += sz;
					}
				}
			}
			currPageSegment = (WPARAM)pageSegment.ListEntry.Flink;
		} while (currPageSegment && currPageSegment != ctxFirstEntry);
	}
	return true;
}

static PDEBUG_BUFFER GetHeapBlocks(DWORD pid, RDebug *dbg) {
	/*
		TODO:
			Break this behemoth
			x86 vs x64 vs WOW64	(use dbg->bits or new structs or just a big union with both versions)
	*/
	if (_M_X64 && dbg->bits == R_SYS_BITS_32) {
		return NULL; // Nope nope nope
	}
	WPARAM bytesRead, ntdllOffset = 0;
	HANDLE h_proc = NULL;
	PDEBUG_BUFFER db = InitHeapInfo (pid, PDI_HEAPS);
	if (!db || !db->HeapInformation) {
		R_LOG_ERROR ("InitHeapInfo Failed\n");
		goto err;
	}
	h_proc = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!h_proc) {
		R_LOG_ERROR ("OpenProcess failed\n");
		goto err;
	}

	WPARAM lfhKey;
	RList  *map_list = w32_dbg_maps (dbg);
	RListIter *iter;
	RDebugMap *map;
	WPARAM lfhKeyLocation;
	// Get ntdll .data location
	r_list_foreach (map_list, iter, map) {
		if (strstr (map->name, "ntdll.dll | .data")) {
			ntdllOffset = map->addr;
			break;
		}
	}
	r_list_free (map_list);
	if (!ntdllOffset) {
		eprintf ("ntdll not loaded\n");
		goto err;
	}

	PHeapInformation heapInfo = db->HeapInformation;
	int i;
	for (i = 0; i < heapInfo->count; i++) {
		WPARAM from = 0;
		ut64 count = 0;
		PDEBUG_HEAP_INFORMATION heap = &heapInfo->heaps[i];
		HEAP_ENTRY heapEntry;
		HEAP heapHeader;
		const SIZE_T sz_entry = sizeof (HEAP_ENTRY);
		ReadProcessMemory (h_proc, heap->Base, &heapHeader, sizeof (HEAP), &bytesRead);

		SIZE_T allocated = 128 * sizeof (HeapBlockBasicInfo);
		PHeapBlockBasicInfo blocks = calloc (allocated, 1);
		if (!blocks) {
			R_LOG_ERROR ("Memory Allocation failed\n");
			goto err;
		}

		// SEGMENT_HEAP
		if (heapHeader.SegmentSignature == 0xddeeddee) {
			bool ret = GetSegmentHeapBlocks (h_proc, heap->Base, &blocks, &count, &allocated, ntdllOffset);
			heap->Blocks = blocks;
			heap->BlockCount = count;
			if (!ret) goto err;
			continue;
		}

		// VirtualAlloc'd blocks
		PLIST_ENTRY fentry = (PVOID)((WPARAM)heapHeader.BaseAddress + offsetof (HEAP, VirtualAllocdBlocks));
		PLIST_ENTRY entry = heapHeader.VirtualAllocdBlocks.Flink;
		while (entry && (entry != fentry)) {
			HEAP_VIRTUAL_ALLOC_ENTRY vAlloc;
			ReadProcessMemory (h_proc, entry, &vAlloc, sizeof (HEAP_VIRTUAL_ALLOC_ENTRY), &bytesRead);
			DecodeHeapEntry (&heapHeader, &vAlloc.BusyBlock);
			GROW_BLOCKS ();
			blocks[count].address = (WPARAM)entry + offsetof (HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);
			blocks[count].flags = 1 | (vAlloc.BusyBlock.Flags | LARGE_BLOCK) & ~2ULL;
			blocks[count].size = vAlloc.CommitSize;
			PHeapBlockExtraInfo extra = calloc (1, sizeof (HeapBlockExtraInfo));
			extra->granularity = sizeof (HEAP_VIRTUAL_ALLOC_ENTRY);
			blocks[count].extra = EXTRA_FLAG | (WPARAM)extra;
			count++;
			entry = vAlloc.Entry.Flink;
		}

		// LFH Activated
		if (heapHeader.FrontEndHeap && heapHeader.FrontEndHeapType == 0x2) {
			lfhKeyLocation = ntdllOffset + 0x7508; // ntdll!RtlpLFHKey
			if (!ReadProcessMemory (h_proc, (PVOID)lfhKeyLocation, &lfhKey, sizeof (WPARAM), &bytesRead)) {
				r_sys_perror ("ReadProcessMemory");
				eprintf ("LFH key not found.\n");
				goto err;
			}
			LFH_HEAP lfhHeader;
			if (!ReadProcessMemory (h_proc, heapHeader.FrontEndHeap, &lfhHeader, sizeof (LFH_HEAP), &bytesRead)) {
				r_sys_perror ("ReadProcessMemory");
				goto err;
			}

			PLIST_ENTRY curEntry, firstEntry = (PVOID)((WPARAM)heapHeader.FrontEndHeap + offsetof (LFH_HEAP, SubSegmentZones));
			curEntry = lfhHeader.SubSegmentZones.Flink;

			// Loops through all _HEAP_SUBSEGMENTs
			do { // (curEntry != firstEntry)
				HEAP_LOCAL_SEGMENT_INFO info;
				HEAP_LOCAL_DATA localData;
				HEAP_SUBSEGMENT subsegment;
				HEAP_USERDATA_HEADER userdata;
				LFH_BLOCK_ZONE blockZone;

				WPARAM curSubsegment = (WPARAM)(curEntry + 2);
				int next = 0;
				do { // (next < blockZone.NextIndex)
					if (!ReadProcessMemory (h_proc, (PVOID)curSubsegment, &subsegment, sizeof (HEAP_SUBSEGMENT), &bytesRead)
						|| !subsegment.BlockSize
						|| !ReadProcessMemory (h_proc, subsegment.LocalInfo, &info, sizeof (HEAP_LOCAL_SEGMENT_INFO), &bytesRead)
						|| !ReadProcessMemory (h_proc, info.LocalData, &localData, sizeof (HEAP_LOCAL_DATA), &bytesRead)
						|| !ReadProcessMemory (h_proc, localData.CrtZone, &blockZone, sizeof (LFH_BLOCK_ZONE), &bytesRead)) {
						break;
					}

					size_t sz = subsegment.BlockSize * sizeof (HEAP_ENTRY);
					ReadProcessMemory (h_proc, subsegment.UserBlocks, &userdata, sizeof (HEAP_USERDATA_HEADER), &bytesRead);
					userdata.EncodedOffsets.StrideAndOffset ^= PtrToInt (subsegment.UserBlocks) ^ PtrToInt (heapHeader.FrontEndHeap) ^ (WPARAM)lfhKey;
					size_t bitmapsz = (userdata.BusyBitmap.SizeOfBitMap + 8 - userdata.BusyBitmap.SizeOfBitMap % 8) / 8;
					WPARAM *bitmap = calloc (bitmapsz > sizeof (WPARAM) ? bitmapsz : sizeof (WPARAM), 1);
					ReadProcessMemory (h_proc, userdata.BusyBitmap.Buffer, bitmap, bitmapsz, &bytesRead);
					WPARAM mask = 1;
					// Walk through the busy bitmap
					for (int j = 0, offset = 0; j < userdata.BusyBitmap.SizeOfBitMap; j++) {
						if (!mask) {
							mask = 1;
							offset++;
						}
						// Only if block is busy
						if (*(bitmap + offset) & mask) {
							GROW_BLOCKS ();
							WPARAM off = userdata.EncodedOffsets.FirstAllocationOffset + sz * j;
							from = (WPARAM)subsegment.UserBlocks + off;
							ReadProcessMemory (h_proc, (PVOID)from, &heapEntry, sz_entry, &bytesRead);
							DecodeLFHEntry (&heapHeader, &heapEntry, subsegment.UserBlocks, lfhKey, from);
							blocks[count].address = from;
							blocks[count].flags = 1 | LFH_BLOCK;
							blocks[count].size = sz;
							PHeapBlockExtraInfo extra = calloc (1, sizeof (HeapBlockExtraInfo));
							extra->granularity = sizeof (HEAP_ENTRY);
							extra->segment = curSubsegment;
							blocks[count].extra = EXTRA_FLAG | (WPARAM)extra;
							count++;
						}
						mask <<= 1;
					}
					free (bitmap);
					curSubsegment += sizeof (HEAP_SUBSEGMENT);
					next++;
				} while (next < blockZone.NextIndex || subsegment.BlockSize);

				LIST_ENTRY entry;
				ReadProcessMemory (h_proc, curEntry, &entry, sizeof (entry), &bytesRead);
				curEntry = entry.Flink;
			} while (curEntry != firstEntry);
		}

		HEAP_SEGMENT oldSegment, segment;
		WPARAM firstSegment = (WPARAM)heapHeader.SegmentList.Flink;
		ReadProcessMemory (h_proc, (PVOID)(firstSegment - offsetof (HEAP_SEGMENT, SegmentListEntry)), &segment, sizeof (HEAP_SEGMENT), &bytesRead);
		// NT Blocks (Loops through all _HEAP_SEGMENTs)
		do {
			from = (WPARAM)segment.FirstEntry;
			if (!from) {
				goto next;
			}
			do {
				if (!ReadProcessMemory (h_proc, (PVOID)from, &heapEntry, sz_entry, &bytesRead)) {
					break;
				}
				DecodeHeapEntry (&heapHeader, &heapEntry);
				if (!heapEntry.Size) {
					// Last Heap block
					count--;
					break;
				}

				SIZE_T real_sz = heapEntry.Size * sz_entry;

				GROW_BLOCKS ();
				PHeapBlockExtraInfo extra = calloc (1, sizeof (HeapBlockExtraInfo));
				extra->granularity = sizeof (HEAP_ENTRY);
				extra->segment = (WPARAM)segment.BaseAddress;
				blocks[count].extra = EXTRA_FLAG | (WPARAM)extra;
				blocks[count].address = from;
				blocks[count].flags = heapEntry.Flags | NT_BLOCK;
				blocks[count].size = real_sz;
				from += real_sz;
				count++;
			} while (from <= (WPARAM)segment.LastValidEntry);
next:
			oldSegment = segment;
			from = (WPARAM)segment.SegmentListEntry.Flink - offsetof (HEAP_SEGMENT, SegmentListEntry);
			ReadProcessMemory (h_proc, (PVOID)from, &segment, sizeof (HEAP_SEGMENT), &bytesRead);
		} while ((WPARAM)oldSegment.SegmentListEntry.Flink != firstSegment);
		heap->Blocks = blocks;
		heap->BlockCount = count;
	}
	CloseHandle (h_proc);
	return db;
err:
	if (h_proc) {
		CloseHandle (h_proc);
	}
	if (db) {
		for (int i = 0; i < heapInfo->count; i++) {
			PDEBUG_HEAP_INFORMATION heap = &heapInfo->heaps[i];
			free_extra_info (heap);
			R_FREE (heap->Blocks);
		}
		RtlDestroyQueryDebugBuffer (db);
	}
	return NULL;
}

static void w32_list_heaps(RCore *core, const char format) {
	ULONG pid = core->dbg->pid;
	PDEBUG_BUFFER db = InitHeapInfo (pid, PDI_HEAPS | PDI_HEAP_BLOCKS);
	if (!db) {
		ut32 major = r_sys_get_winver () / 1000000;
		if (major >= 10) {
			db = GetHeapBlocks (pid, core->dbg);
		}
		if (!db) {
			eprintf ("Couldn't get heap info.\n");
			return;
		}
	}
	PHeapInformation heapInfo = db->HeapInformation;
	CHECK_INFO (heapInfo);
	int i;
	PJ *pj = pj_new ();
	pj_a (pj);
	for (i = 0; i < heapInfo->count; i++) {
		DEBUG_HEAP_INFORMATION heap = heapInfo->heaps[i];
		switch (format) {
		case 'j':
			pj_o (pj);
			pj_kN (pj, "address", (WPARAM)heap.Base);
			pj_kN (pj, "count", (WPARAM)heap.BlockCount);
			pj_kN (pj, "allocated", (WPARAM)heap.Allocated);
			pj_kN (pj, "commited", (WPARAM)heap.Committed);
			pj_end (pj);
			break;
		default:
			r_cons_printf ("Heap @ 0x%08"PFMT64x":\n", (WPARAM)heap.Base);
			r_cons_printf ("\tBlocks: %"PFMT64u"\n", (WPARAM)heap.BlockCount);
			r_cons_printf ("\tAllocated: %"PFMT64u"\n", (WPARAM)heap.Allocated);
			r_cons_printf ("\tCommited: %"PFMT64u"\n", (WPARAM)heap.Committed);
			break;
		}
		if (!(db->InfoClassMask & PDI_HEAP_BLOCKS)) {
			free_extra_info (&heap);
			R_FREE (heap.Blocks);
		}
	}
	if (format == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
	}
	pj_free (pj);
	RtlDestroyQueryDebugBuffer (db);
}

static void w32_list_heaps_blocks(RCore *core, const char format) {
	DWORD pid = core->dbg->pid;
	PDEBUG_BUFFER db = InitHeapInfo (pid, PDI_HEAPS | PDI_HEAP_BLOCKS | PDI_HEAP_ENTRIES_EX);
	if (!db) {
		// Too many blocks or segment heap (will block if segment heap)
		ut32 major = r_sys_get_winver () / 1000000;
		if (major >= 10) { // Only tested on 10. Maybe works on 8
			db = GetHeapBlocks (pid, core->dbg);
		}
		if (!db) {
			eprintf ("Couldn't get heap info.\n");
			return;
		}
	}
	PHeapInformation heapInfo = db->HeapInformation;
	HeapBlock *block = malloc (sizeof (HeapBlock));
	CHECK_INFO (heapInfo);
	int i;
	PJ *pj = pj_new ();
	pj_a (pj);
	for (i = 0; i < heapInfo->count; i++) {
		bool go = true;
		switch (format) {
		case 'f':
			if (heapInfo->heaps[i].BlockCount > 50000) {
				go = r_cons_yesno ('n', "Are you sure you want to add %"PFMT64u" flags? (y/N)", heapInfo->heaps[i].BlockCount);
			}
			break;
		case 'j':
			pj_o (pj);
			pj_kN (pj, "heap", (WPARAM)heapInfo->heaps[i].Base);
			pj_k (pj, "blocks");
			pj_a (pj);
			break;
		default:
			r_cons_printf ("Heap @ 0x%"PFMT64x":\n", heapInfo->heaps[i].Base);
		}
		if (GetFirstHeapBlock (&heapInfo->heaps[i], block) & go) {
			do {
				char *type = "";
				switch (block->dwFlags) {
				case LF32_FIXED:
					type = "(FIXED)";
					break;
				case LF32_FREE:
					type = "(FREE)";
					break;
				case LF32_MOVEABLE:
					type = "(MOVEABLE)";
					break;
				}
				unsigned short granularity = block->extraInfo ? block->extraInfo->granularity : heapInfo->heaps[i].Granularity;
				switch (format) {
				case 'f':
				{
					ut64 addr = (ut64)block->dwAddress - granularity;
					char *name = r_str_newf ("alloc.%"PFMT64x"", addr);
					r_flag_set (core->flags, name, addr, block->dwSize);
					free (name);
					break;
				}
				case 'j':
				{
					pj_o (pj);
					pj_kN (pj, "address", (ut64)block->dwAddress - granularity);
					pj_kN (pj, "data_address", (ut64)block->dwAddress);
					pj_kN (pj, "size", block->dwSize);
					pj_ks (pj, "type", type);
					pj_end (pj);
					break;
				}
				default: 
					{
						r_cons_printf ("\tBlock @ 0x%"PFMT64x" %s:\n", (ut64)block->dwAddress - granularity, type);
						r_cons_printf ("\t\tSize 0x%"PFMT64x"\n", (ut64)block->dwSize);
						r_cons_printf ("\t\tData address @ 0x%"PFMT64x"\n", (ut64)block->dwAddress);
						break;
					}
				}
			} while (GetNextHeapBlock (&heapInfo->heaps[i], block));
		}
		if (format == 'j') {
			pj_end (pj);
			pj_end (pj);
		}
		if (!(db->InfoClassMask & PDI_HEAP_BLOCKS)) {
			// RtlDestroyQueryDebugBuffer wont free this for some reason
			free_extra_info (&heapInfo->heaps[i]);
			R_FREE (heapInfo->heaps[i].Blocks);
		}
	}
	if (format == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
	}
	pj_free (pj);
	RtlDestroyQueryDebugBuffer (db);
}

static const char* help_msg[] = {
	"Usage:", " dmh[b|f][?]", " # Memory map heap",
	"dmh[j]", "", "List process heaps",
	"dmhb[f|?]", "", "List process heap blocks",
	"dmh?", "", "Show map heap help",
	NULL
};

static const char* help_msg_block[] = {
	"Usage:", " dmhb[f|j]", " # Memory map heap",
	"dmhbf", "", "Create flags for each allocation block",
	"dmhbj", "", "Print output in JSON format",
	NULL
};

static void cmd_debug_map_heap_block_win(RCore *core, const char *input) {
	switch (input[0]) {
	case '\0':
	case 'f':
	case 'j':
		w32_list_heaps_blocks (core, input[0]);
		break;
	default:
		r_core_cmd_help (core, help_msg_block);
	}
}

static int cmd_debug_map_heap_win(RCore *core, const char *input) {
	init_func ();
	switch (input[0]) {
	case '?': // dmh?
		r_core_cmd_help (core, help_msg);
		break;
	case 'b': // dmhb
		cmd_debug_map_heap_block_win (core, input + 1);
		break;
	default:
		w32_list_heaps (core, input[0]);
		break;
	}
	return true;
}